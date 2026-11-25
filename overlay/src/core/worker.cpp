// SPDX-License-Identifier: GPL-3.0-or-later
#include "protocol.hpp"
#include "hook.hpp"
#include "../app/overlay_ui.hpp"
#include "../app/overlay_app.cpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
using namespace overlay;
#ifndef OVERLAY_BUILD
#define OVERLAY_BUILD 0ULL
#endif
namespace {
using Object=void;using Method=void;using Update=void(*)(Object*);
using PadCall=PadData(*)(int);
using ShareCall=void(*)(void*);
using AudioOutInitCall=int(*)();
using AudioOutOpenCall=int(*)(int,int,int,unsigned int,unsigned int,unsigned int);
using AudioOutOutputCall=int(*)(int,const void*);
using AudioOutCloseCall=int(*)(int);
using AudioInOpenCall=int(*)(int,int,int,unsigned int,unsigned int,unsigned int);
using AudioInInputCall=int(*)(int,void*);
using AudioInCloseCall=int(*)(int);
using UserForegroundCall=int(*)(int*);
constexpr int kind_void=1,kind_class=0x12,kind_valuetype=0x11;
constexpr std::uint32_t bit_l3=0x4000,bit_r3=0x8000;
// Hold Options: the game takes the press first (most open their pause menu), then the
// panel opens over it: the pause for games that do not pause for the system menu.
constexpr std::uint32_t bit_options=0x100;
std::atomic<std::uint64_t> options_hold_ms{600}; // the app's setting (Builder::set_hold)
constexpr unsigned create_attempt_limit=3,create_delay_ticks=30,text_period_ticks=12;
Request request;
Hook update_hook_store,pad_hook_store,share_hook_store;
// ---- Mode::BundleDump (lab): run_bundle_dump() reads the bundle file and decrypts it in place by
// calling the RNPS kernel-decrypt routine directly (libSceRnpsBundle sub_6f80, which opens /dev/rnps
// and ioctls the buffer). No hook, no user action, no system write; it keeps no globals of its own.
constexpr std::uint32_t kRnpsDecryptOffset=0x6f80;      // sub_6f80 in libSceRnpsBundle, relative to...
constexpr std::uint32_t kRnpsVerifyExportOffset=0x1050; // ...sceRnpsBundleVerifyAndDecrypt (eqd58iI3rv8)
void* domain=nullptr;
void* resolved_update_entry=nullptr;
Method* find_scene=nullptr;
Method* root_getter=nullptr;
void* class_widget=nullptr,*class_panel=nullptr,*class_label=nullptr,*class_font=nullptr;
void* class_application=nullptr,*class_scene=nullptr;
Method* method_append=nullptr,*method_find=nullptr,*method_font_ctor=nullptr;
// Pictures (optional: without them the overlay has panels and text only).
void* class_image=nullptr,*class_asset=nullptr;Method* method_asset_ctor=nullptr;
Method* method_text_width=nullptr; // Label.GetTextWidth(): where the keyboard's caret goes
std::atomic<Update> original{nullptr};
std::atomic<PadCall> pad_original{nullptr};
std::atomic<ShareCall> share_original{nullptr};
std::atomic<bool> enabled{false},input_enabled{false},teardown{false};
std::atomic<std::uint64_t> updates{0},pad_polls{0};
std::atomic<unsigned> scene_attempts{0},create_attempts{0},text_updates{0},share_events{0},chords{0},double_presses{0};
std::atomic<std::uint32_t> last_buttons{0};
std::atomic<std::uint64_t> last_share_at{0};
std::atomic<int> game_found{0},root_found{0},widgets_created{0},widget_removed{0};
std::atomic<bool> chord_held{false},gesture_requested{false},options_fired{false};
std::atomic<std::uint64_t> options_since{0};
// Capture (the app's panel is open): pad_hook ORs newly pressed buttons in and keeps the
// left stick; the UI thread hands them to app::on_pad.
std::atomic<bool> capture{false};
std::atomic<std::uint32_t> pending_down{0},stick_x{0},stick_y{0};
std::atomic<unsigned> pad_logged{0};
std::uint64_t command_seq=0;                 // UI thread only
// Holding the game while the panel is open (the system menu's way): the impose status set
// and controller focus with the system. game_app is whose focus to give back.
std::atomic<bool> holding{false};
std::atomic<bool> repeat_reset{false}; // capture went on: no button counts as held from before
std::atomic<int> game_app{-1};
std::atomic<std::uint64_t> last_input_ms{0};
#ifndef OVERLAY_APP_LAB
constexpr std::uint64_t hold_idle_ms=30000;  // no button reaches us this long: give it back
#endif
// UI thread only. Pinned (1) handles like the reference: scene graph objects
// and the captured Application instance survive GC moves.
std::uint32_t app_handle=0,root_scene_handle=0,scene_handle=0,scene_root_handle=0;
bool removal_requested=false,cleanup_retry_used=false;
constexpr std::size_t text_limit=2048;      // text.bin, bytes
constexpr std::size_t chat_limit=16384;     // chat.bin, bytes
char last_text[text_limit]{};                // UI thread only
char last_chat[chat_limit]{};                // UI thread only
float ui_screen_w=1920,ui_screen_h=1080;     // UI thread only
struct WidgetSlot{std::uint32_t handle=0,asset=0;bool label=false;char path[160]{};};
// 192: the Chat and Mentions tabs add 44 widgets (the Discord UI builds 170). A slot is a
// 172-byte record, a pinned GC handle for the widget and one more for a picture's asset: 192 slots
// are 33 KB and at most 384 handles, the same kind of cost as the 160 before.
constexpr std::uint32_t widget_limit=192;
WidgetSlot widget_slots[widget_limit];       // UI thread only, app-facing ids
static_assert(std::atomic<Update>::is_always_lock_free&&std::atomic<PadCall>::is_always_lock_free&&
    std::atomic<ShareCall>::is_always_lock_free&&std::atomic<std::uint64_t>::is_always_lock_free);
static_assert(sizeof(PadData)==36&&offsetof(PadData,buttons)==4&&offsetof(PadData,down)==12&&
    offsetof(PadData,lx)==20&&offsetof(PadData,ry)==32);
template<class T>T fn(Function which){return reinterpret_cast<T>(request.functions[which]);}
void note(const char* format,...){
    char p[256];if(!path(p,sizeof p,worker_dir,"worker.log"))return;
    FILE* f=std::fopen(p,"a");if(!f)return;
    std::fprintf(f,"[overlay-worker pid=%d token=%llu ms=%llu] ",getpid(),(unsigned long long)request.token,(unsigned long long)now_ms());
    va_list ap;va_start(ap,format);std::vfprintf(f,format,ap);va_end(ap);std::fputc('\n',f);std::fclose(f);
}
void* invoke(Method* method,void* instance,void** args,bool& ok){
    void* exception=nullptr;void* result=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(method,instance,args,&exception);
    ok=exception==nullptr;return result;
}
bool signature(Method* m,bool instance,unsigned count,int return_kind){
    void* sig=fn<void*(*)(void*)>(MethodSignature)(m);if(!sig)return false;
    if(bool(fn<int(*)(void*)>(SignatureInstance)(sig))!=instance||fn<unsigned(*)(void*)>(SignatureCount)(sig)!=count)return false;
    void* type=fn<void*(*)(void*)>(SignatureReturn)(sig);return type&&fn<int(*)(void*)>(TypeKind)(type)==return_kind;
}
void* image(const char* path){
    void* assembly=fn<void*(*)(void*,const char*)>(AssemblyOpen)(domain,path);
    return assembly?fn<void*(*)(void*)>(AssemblyImage)(assembly):nullptr;
}
Method* method(void* img,const char* ns,const char* klass,const char* name,int count){
    if(!img)return nullptr;void* type=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img,ns,klass);
    return type?fn<void*(*)(void*,const char*,int)>(MethodFromName)(type,name,count):nullptr;
}
// Property access: the compiled accessor is called directly for ABI-simple
// parameters and through mono_runtime_invoke for value-type parameters, which
// boxes from the pointed-to bytes.
// kabuki-style: every accessor through mono_runtime_invoke (13.x-proven);
// managed exceptions are logged with their type name.
void* invoke_ex(Method* method,void* instance,void** args,bool& ok,void** exception){
    void* result=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(method,instance,args,exception);
    ok=*exception==nullptr;return result;
}
bool describe_exception(const char* what,void* exception){
    if(!exception)return true;
    void* type=fn<void*(*)(void*)>(ObjectClass)(exception);
    const char* name=type?fn<const char*(*)(void*)>(ClassNameGet)(type):nullptr;
    note("EXC %s type=%s",what,name?name:"?");
    return false;
}
// value: for value-type parameters a pointer to the bytes; for reference
// parameters (string, font) the object pointer itself.
Method* method_inherited(void* klass,const char* name,int count){
    for(void* walk=klass;walk;){
        if(Method* m=fn<Method*(*)(void*,const char*,int)>(MethodFromName)(walk,name,count))return m;
        walk=fn<void*(*)(void*)>(ClassParent)(walk);}
    return nullptr;
}
// The overload of name whose one parameter has this type (ImageAsset has two 1-argument
// constructors: a file's URI and a texture).
Method* method_taking(void* klass,const char* name,const char* param){
    void* iter=nullptr;
    for(int i=0;klass&&i<400;i++){
        Method* m=fn<Method*(*)(void*,void**)>(ClassMethods)(klass,&iter);if(!m)break;
        const char* n=fn<const char*(*)(void*)>(MethodName)(m);
        if(!n||std::strcmp(n,name))continue;
        void* sig=fn<void*(*)(void*)>(MethodSignature)(m);
        if(!sig||fn<unsigned(*)(void*)>(SignatureCount)(sig)!=1)continue;
        void* piter=nullptr;void* type=fn<void*(*)(void*,void**)>(SignatureParams)(sig,&piter);
        const char* t=type?fn<const char*(*)(void*)>(TypeName)(type):nullptr;
        if(t&&!std::strcmp(t,param))return m;}
    return nullptr;
}
bool prop_get_object(void* klass,void* obj,const char* name,void** out){
    if(!klass||!obj||!out)return false;
    void* prop=fn<void*(*)(void*,const char*)>(ClassProperty)(klass,name);
    if(!prop){note("PROP miss get %s",name);return false;}
    Method* getter=fn<Method*(*)(void*)>(PropertyGetter)(prop);
    if(!getter){note("PROP write-only %s",name);return false;}
    void* exception=nullptr;bool ok=false;
    void* result=invoke_ex(getter,obj,nullptr,ok,&exception);
    if(!ok){describe_exception(name,exception);return false;}
        *out=result;return result!=nullptr;
}
bool prop_get_bool(void* klass,void* obj,const char* name,bool* out){
    void* result=nullptr;
    if(!prop_get_object(klass,obj,name,&result))return false;
    void* unboxed=fn<void*(*)(void*)>(ObjectUnbox)(result);
    if(!unboxed)return false;
    *out=*static_cast<unsigned char*>(unboxed)!=0;return true;
}
bool prop_set(void* klass,void* obj,const char* name,void* value){
    if(!klass||!obj)return false;
    void* prop=fn<void*(*)(void*,const char*)>(ClassProperty)(klass,name);
    if(!prop){note("PROP miss %s",name);return false;}
    Method* setter=fn<Method*(*)(void*)>(PropertySetter)(prop);
    if(!setter){note("PROP read-only %s",name);return false;}
    void* args[1];args[0]=value;void* exception=nullptr;bool ok=false;
    invoke_ex(setter,obj,args,ok,&exception);
    if(!ok){describe_exception(name,exception);return false;}
    return true;
}
bool prop_set_float(void* k,void* o,const char* n,float v){return prop_set(k,o,n,&v);}
bool prop_set_int(void* k,void* o,const char* n,int v){return prop_set(k,o,n,&v);}
bool prop_get_float(void* klass,void* obj,const char* name,float& out){
    if(!klass||!obj)return false;
    void* prop=fn<void*(*)(void*,const char*)>(ClassProperty)(klass,name);
    if(!prop){note("PROP miss get %s",name);return false;}
    Method* getter=fn<Method*(*)(void*)>(PropertyGetter)(prop);
    if(!getter){note("PROP write-only %s",name);return false;}
    void* exception=nullptr;bool ok=false;
    void* result=invoke_ex(getter,obj,nullptr,ok,&exception);
    if(!ok||!result){describe_exception(name,exception);return false;}
    void* unboxed=fn<void*(*)(void*)>(ObjectUnbox)(result);
    if(!unboxed)return false;
    out=*static_cast<float*>(unboxed);return true;
}
// Sce.PlayStation.PUI.UIColor on 13.00 (logged by describe_types, 2026-11-03): four floats
// and an HDR flag, 20 bytes. 12.x's float[4] left the flag to whatever followed on the
// stack, and a set flag turned every colour white.
struct UiColor {float r,g,b,a;bool hdr;char pad[3];};
static_assert(sizeof(UiColor)==20);
// The app's colours are sRGB (as on any screen); PUI blends in linear light, so dark ones
// came out light (#22252c showed as a pale grey-blue on 13.00). Alpha stays as it is.
float linear(float v){return v<=0.04045f?v/12.92f:std::pow((v+0.055f)/1.055f,2.4f);}
UiColor ui_color(const oui::Color& c){return UiColor{linear(c.r),linear(c.g),linear(c.b),c.a,false,{}};}
// Our colours, not the system skin's (Widget.FollowSkin*).
void no_skin(void* klass,void* widget){
    int no=0;
    (void)prop_set_int(klass,widget,"FollowSkinBackgroundColor",no);
    (void)prop_set_int(klass,widget,"FollowSkinFontColor",no);
}
void observe_scene(){
    scene_attempts.fetch_add(1,std::memory_order_relaxed);
    auto text=fn<void*(*)(void*,const char*)>(StringNew)(domain,"Game");if(!text)return;
    void* args[]={text};bool ok=false;void* scene=invoke(find_scene,nullptr,args,ok);if(!ok||!scene)return;
    auto handle=fn<std::uint32_t(*)(void*,int)>(GcNew)(scene,0);if(!handle)return;
    scene=fn<void*(*)(std::uint32_t)>(GcTarget)(handle);
    if(scene){game_found.store(1,std::memory_order_release);
        void* root=invoke(root_getter,scene,nullptr,ok);if(ok&&root)root_found.store(1,std::memory_order_release);}
    fn<void(*)(std::uint32_t)>(GcFree)(handle);
}
bool append_child(void* parent,void* child){
    void* args[1];args[0]=child;bool ok=false;invoke(method_append,parent,args,ok);return ok;
}
// A feed file into out (NUL-terminated): false when it is missing, too long for limit, or holds a NUL.
template<std::size_t Limit>bool load_feed(const char* name,char* out,std::size_t n){
    char p[256];if(!path(p,sizeof p,worker_dir,name))return false;
    FILE* f=std::fopen(p,"rb");if(!f)return false;
    static char raw[Limit]; // UI thread only; the chat feed is too big for the stack
    std::size_t got=std::fread(raw,1,sizeof raw,f);
    // A full buffer means the file is too long: never display a silent prefix.
    bool ok=!std::ferror(f)&&got<sizeof raw&&!std::memchr(raw,0,got);
    std::fclose(f);if(!ok||!got)return false;
    while(got&&(raw[got-1]=='\n'||raw[got-1]=='\r'))--got;
    if(got&&(raw[got-1]&0xc0)==0x80){ // may end inside a multi-byte sequence
        std::size_t run=1;
        while(run<got&&run<4&&(raw[got-run]&0xc0)==0x80)++run;
        std::uint8_t lead=raw[got-run];
        std::size_t need=(lead&0xe0)==0xc0?2:(lead&0xf0)==0xe0?3:(lead&0xf8)==0xf0?4:0;
        if(need!=run)got-=(need==0?run-1:run); // orphan continuations vs truncated/malformed sequence
    }
    if(!got||got+1>n)return false;
    std::memcpy(out,raw,got);out[got]=0;return true;
}
// ---- oui::Builder engine implementation (all UI-thread) --------------------
void* slot_object(std::uint32_t index){
    return index&&index<=widget_limit&&widget_slots[index-1].handle?
        fn<void*(*)(std::uint32_t)>(GcTarget)(widget_slots[index-1].handle):nullptr;}
std::uint32_t slot_store(void* object,bool label){
    for(auto& slot:widget_slots){
        if(slot.handle)continue;
        slot.handle=fn<std::uint32_t(*)(void*,int)>(GcNew)(object,1);
        slot.label=label;slot.asset=0;slot.path[0]=0;
        return slot.handle?std::uint32_t(&slot-widget_slots)+1:0;}
    return 0;}
void slots_release(){
    for(auto& slot:widget_slots){
        if(slot.asset){fn<void(*)(std::uint32_t)>(GcFree)(slot.asset);slot.asset=0;}
        if(slot.handle){fn<void(*)(std::uint32_t)>(GcFree)(slot.handle);slot.handle=0;}}
}
// Log-only: the value type a property takes on this firmware, field by field (offsets
// include the 16-byte object header), and the class's property names. Colours and fonts
// did not render on 13.00 with 12.x's float[4]; this says what they are.
void describe_property(void* klass,const char* cls,const char* name){
    void* prop=klass?fn<void*(*)(void*,const char*)>(ClassProperty)(klass,name):nullptr;
    Method* setter=prop?fn<Method*(*)(void*)>(PropertySetter)(prop):nullptr;
    void* sig=setter?fn<void*(*)(void*)>(MethodSignature)(setter):nullptr;
    void* iter=nullptr;void* type=sig?fn<void*(*)(void*,void**)>(SignatureParams)(sig,&iter):nullptr;
    const char* type_name=type?fn<const char*(*)(void*)>(TypeName)(type):nullptr;
    note("TYPE %s.%s = %s (kind %d)",cls,name,type_name?type_name:"?",type?fn<int(*)(void*)>(TypeKind)(type):-1);
    void* k=type?fn<void*(*)(void*)>(ClassFromType)(type):nullptr;
    void* fields=nullptr;
    for(int i=0;k&&i<16;i++){
        void* f=fn<void*(*)(void*,void**)>(ClassFields)(k,&fields);if(!f)break;
        void* ft=fn<void*(*)(void*)>(FieldType)(f);
        const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
        const char* ftype=ft?fn<const char*(*)(void*)>(TypeName)(ft):nullptr;
        note("TYPE   field %s : %s @%u",fname?fname:"?",ftype?ftype:"?",fn<unsigned(*)(void*)>(FieldOffset)(f));}
}
void describe_properties(void* klass,const char* cls){
    char line[900];int at=std::snprintf(line,sizeof line,"PROPS %s:",cls);
    void* iter=nullptr;
    for(int i=0;klass&&i<120;i++){
        void* p=fn<void*(*)(void*,void**)>(ClassProperties)(klass,&iter);if(!p)break;
        const char* n=fn<const char*(*)(void*)>(PropertyName)(p);
        if(n&&at>0&&at<int(sizeof line)-40)at+=std::snprintf(line+at,sizeof line-at," %s",n);}
    note("%s",line);
}
void describe_types(){
    describe_property(class_panel,"Panel","BackgroundColor");
    describe_property(class_label,"Label","TextColor");
    describe_property(class_label,"Label","Font");
    describe_property(class_widget,"Widget","Opacity");
    describe_properties(class_widget,"Widget");
    describe_properties(class_panel,"Panel");
    describe_properties(class_label,"Label");
}
void* engine_add_panel(void*,const oui::Rect* r,const oui::Color* c){
    void* root=scene_root_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(scene_root_handle):nullptr;
    if(!root||!r)return nullptr;
    void* panel=fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_panel);
    if(!panel)return nullptr;
    fn<void(*)(void*)>(ObjectInit)(panel);
    int passive=0,shown=1;
    if(!prop_set_int(class_panel,panel,"Focusable",passive)||
       !prop_set_float(class_panel,panel,"X",r->x)||
       !prop_set_float(class_panel,panel,"Y",r->y)||
       !prop_set_float(class_panel,panel,"Width",r->w)||
       !prop_set_float(class_panel,panel,"Height",r->h)||
       !prop_set_int(class_panel,panel,"Visible",shown)){note("UI panel props failed");return nullptr;}
    // Alpha inside the colour (Opacity would fade the children too).
    no_skin(class_panel,panel);
    UiColor back=ui_color(*c);
    (void)prop_set(class_panel,panel,"BackgroundColor",&back);
    if(!append_child(root,panel)){note("UI panel attach failed");return nullptr;}
    std::uint32_t id=slot_store(panel,false);
    return id?reinterpret_cast<void*>(std::uintptr_t(id)):nullptr;}
// Kabuki's 12.x label recipe (Font and TextColor were left out of the first 13.00 runs):
// a UIFont value built with its (size, style, weight) constructor and set unboxed, the
// text colour as float[4], and the system theme's colours off. A missing property only
// logs (prop_set), the label stays.
std::atomic<unsigned> font_failures{0};
void style_label(void* label,float height,int weight=0){
    if(void* boxed=method_font_ctor?fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_font):nullptr){
        std::uint32_t pin=fn<std::uint32_t(*)(void*,int)>(GcNew)(boxed,1);
        void* font=pin?fn<void*(*)(void*)>(ObjectUnbox)(fn<void*(*)(std::uint32_t)>(GcTarget)(pin)):nullptr;
        int size=int(height*0.62f+0.5f),style=0;
        void* args[3]={&size,&style,&weight};void* exception=nullptr;bool ok=false;
        if(font)invoke_ex(method_font_ctor,font,args,ok,&exception);
        if(font&&ok)(void)prop_set(class_label,label,"Font",font);
        else if(font_failures.fetch_add(1)<3)describe_exception("UIFont.ctor",exception);
        if(pin)fn<void(*)(std::uint32_t)>(GcFree)(pin);}
    no_skin(class_label,label);
    UiColor white=ui_color(oui::Color{});
    (void)prop_set(class_label,label,"TextColor",&white);
    int no=0,one=1;
    (void)prop_set_int(class_label,label,"EnableThemedColor",no);
    // On, Text is read as a localisation id: our words drew nothing (Kabuki turns it off).
    (void)prop_set_int(class_label,label,"EnableStringifiedJsonWithId",no);
    (void)prop_set_int(class_label,label,"MaxLineCount",one);
}
void* engine_add_label(void*,void* parent,const oui::Rect* r,const char* text){
    void* owner=parent?slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(parent)))
                      :(scene_root_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(scene_root_handle):nullptr);
    if(!owner||!r||!text)return nullptr;
    void* label=fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_label);
    if(!label)return nullptr;
    fn<void(*)(void*)>(ObjectInit)(label);
    int passive=0,shown=1;
    style_label(label,r->h);
    if(!prop_set_int(class_label,label,"Focusable",passive)||
       !prop_set_float(class_label,label,"X",r->x)||
       !prop_set_float(class_label,label,"Y",r->y)||
       !prop_set_float(class_label,label,"Width",r->w)||
       !prop_set_float(class_label,label,"Height",r->h)||
       !prop_set_int(class_label,label,"Visible",shown)||
       !prop_set(class_label,label,"Text",fn<void*(*)(void*,const char*)>(StringNew)(domain,text))){
        note("UI label props failed");return nullptr;}
    if(!append_child(owner,label)){note("UI label attach failed");return nullptr;}
    std::uint32_t id=slot_store(label,true);
    return id?reinterpret_cast<void*>(std::uintptr_t(id)):nullptr;}
bool engine_set_text(void*,void* widget,const char* text){
    void* label=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    if(!label||!text)return false;
    return prop_set(class_label,label,"Text",fn<void*(*)(void*,const char*)>(StringNew)(domain,text));}
bool engine_set_visible(void*,void* widget,bool show){
    int state=show?1:0;
    if(!widget){
        void* root=scene_root_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(scene_root_handle):nullptr;
        return root&&prop_set_int(class_widget,root,"Visible",state);}
    void* object=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    if(!object)return false;
    void* type=fn<void*(*)(void*)>(ObjectClass)(object);
    return type&&prop_set_int(type,object,"Visible",state);}
bool engine_set_color(void*,void* panel,const oui::Color* c){
    void* object=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(panel)));
    if(!object||!c)return false;
    UiColor back=ui_color(*c);
    return prop_set(class_panel,object,"BackgroundColor",&back);}
float engine_screen_w(void*){return ui_screen_w;}
float engine_screen_h(void*){return ui_screen_h;}
void hold_game(){
    if(holding.load()||!request.functions[SetControllerFocus])return;
    int app=request.functions[RunningBigApp]?fn<int(*)()>(RunningBigApp)():-1;
    int impose=request.functions[SetImposeStatus]?fn<int(*)(int)>(SetImposeStatus)(1):-1;
    int focus=request.shell_app>0?fn<int(*)(int)>(SetControllerFocus)(request.shell_app):-1;
    note("HOLD game=%x shell=%x impose=%x focus=%x",app,unsigned(request.shell_app),impose,focus);
    game_app.store(app);last_input_ms.store(now_ms());holding.store(true);
}
void release_game(const char* why){
    if(!holding.exchange(false))return;
    int app=game_app.load();
    int focus=app>0?fn<int(*)(int)>(SetControllerFocus)(app):-1;
    int impose=request.functions[SetImposeStatus]?fn<int(*)(int)>(SetImposeStatus)(0):-1;
    note("RELEASE (%s) game=%x focus=%x impose=%x",why,app,focus,impose);
}
bool engine_set_capture(void*,bool on){
    if(on)repeat_reset.store(true,std::memory_order_release);
    if(on&&!capture.load(std::memory_order_relaxed))pending_down.store(0,std::memory_order_relaxed);
    capture.store(on,std::memory_order_release);
    if(on)hold_game();else release_game("closed");
    return true;}
bool engine_send(void*,const char* text){
    if(!text)return false;
    Command c;c.seq=now_ms()*64+(++command_seq%64); // grows across runs too
    std::snprintf(c.text,sizeof c.text,"%s",text);
    note("COMMAND %s",c.text);
    return write_file(worker_dir,"cmd.bin",c);}
// A label's text width in px (PUI lays it out from the font), or -1 when it cannot say.
float engine_text_width(void*,void* widget){
    void* label=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    if(!label||!method_text_width)return -1;
    bool ok=false;void* exception=nullptr;void* boxed=invoke_ex(method_text_width,label,nullptr,ok,&exception);
    if(!ok){describe_exception("GetTextWidth",exception);return -1;}
    void* v=boxed?fn<void*(*)(void*)>(ObjectUnbox)(boxed):nullptr;
    float w=-1;if(v)std::memcpy(&w,v,4);
    static int logged=0;if(logged<8){logged++;note("TEXT width=%.1f",w);}
    return w;}
bool engine_send_text(void*,const char* text,const char* channel){
    static Outbox box; // UI thread only; 8 KB stays off the stack
    const std::size_t n=text?std::strlen(text):0,c=channel?std::strlen(channel):0;
    if(!n||n>=sizeof box.text||c>=sizeof box.channel)return false;
    box.seq=now_ms()*64+(++command_seq%64);box.len=std::uint32_t(n);
    std::memset(box.channel,0,sizeof box.channel);if(c)std::memcpy(box.channel,channel,c);
    std::memset(box.text,0,sizeof box.text);std::memcpy(box.text,text,n);
    note("SEND %u bytes",box.len);
    return write_file(worker_dir,"send.bin",box);}
// Kabuki's picture recipe: an ImageBox whose Image is an ImageAsset made from "file://path".
WidgetSlot* slot_of(void* widget){
    auto index=static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget));
    return index&&index<=widget_limit&&widget_slots[index-1].handle?&widget_slots[index-1]:nullptr;}
bool engine_set_image(void*,void* widget,const char* path){
    WidgetSlot* slot=slot_of(widget);void* box=slot?slot_object(std::uint32_t(slot-widget_slots)+1):nullptr;
    if(!box||!path||!class_asset||!method_asset_ctor)return false;
    if(!std::strcmp(slot->path,path))return true;
    void* asset=nullptr;std::uint32_t pin=0;
    if(path[0]&&access(path,R_OK)==0){
        char uri[200];std::snprintf(uri,sizeof uri,"file://%s",path);
        void* text=fn<void*(*)(void*,const char*)>(StringNew)(domain,uri);
        asset=text?fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_asset):nullptr;
        pin=asset?fn<std::uint32_t(*)(void*,int)>(GcNew)(asset,1):0;
        void* args[1]={text};void* exception=nullptr;bool ok=false;
        if(pin)invoke_ex(method_asset_ctor,fn<void*(*)(std::uint32_t)>(GcTarget)(pin),args,ok,&exception);
        if(!pin||!ok){describe_exception("ImageAsset",exception);if(pin)fn<void(*)(std::uint32_t)>(GcFree)(pin);return false;}
        asset=fn<void*(*)(std::uint32_t)>(GcTarget)(pin);}
    if(!prop_set(class_image,box,"Image",asset)){if(pin)fn<void(*)(std::uint32_t)>(GcFree)(pin);return false;}
    if(slot->asset)fn<void(*)(std::uint32_t)>(GcFree)(slot->asset);
    slot->asset=pin;std::snprintf(slot->path,sizeof slot->path,"%s",path);
    return true;}
void* engine_add_image(void*,const oui::Rect* r,const char* path){
    void* root=scene_root_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(scene_root_handle):nullptr;
    if(!root||!r||!class_image||!class_asset)return nullptr;
    void* box=fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_image);
    if(!box)return nullptr;
    fn<void(*)(void*)>(ObjectInit)(box);
    int no=0,shown=1,stretch=1;
    if(!prop_set_int(class_image,box,"Focusable",no)||
       !prop_set_float(class_image,box,"X",r->x)||!prop_set_float(class_image,box,"Y",r->y)||
       !prop_set_float(class_image,box,"Width",r->w)||!prop_set_float(class_image,box,"Height",r->h)||
       !prop_set_int(class_image,box,"Visible",shown)){note("UI image props failed");return nullptr;}
    (void)prop_set_int(class_image,box,"DisposeImageOutOfScreen",no);
    (void)prop_set_int(class_image,box,"ImageScaleType",stretch);
    no_skin(class_image,box);
    if(!append_child(root,box)){note("UI image attach failed");return nullptr;}
    std::uint32_t id=slot_store(box,false);
    void* widget=id?reinterpret_cast<void*>(std::uintptr_t(id)):nullptr;
    if(widget&&path&&path[0]&&!engine_set_image(nullptr,widget,path))note("UI image %s not shown",path);
    return widget;}
bool engine_set_tint(void*,void* widget,const oui::Color* c){
    void* object=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    if(!object||!c||!class_image)return false;
    // Not linear(): PUI draws pictures as stored, so the tint multiplies those values directly
    // (a linear grey 0.235 came out near black on 13.00, coral turned red).
    UiColor tint{c->r,c->g,c->b,c->a,false,{}};
    return prop_set(class_image,object,"FilterColor",&tint);}
bool engine_set_text_style(void*,void* widget,float size,int weight,const oui::Color* c,int align){
    void* label=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    if(!label||!c)return false;
    style_label(label,size/0.62f,weight);
    UiColor ink=ui_color(*c);
    (void)prop_set(class_label,label,"TextColor",&ink);
    int trim=3;
    (void)prop_set_int(class_label,label,"HorizontalAlignment",align);
    (void)prop_set_int(class_label,label,"TextTrimming",trim);
    return true;}
bool engine_set_text_valign(void*,void* widget,int v){
    void* label=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    return label&&prop_set_int(class_label,label,"VerticalAlignment",v);} // UI2.VerticalAlignment: Top 0, Bottom 1, Center 2
bool engine_set_rect(void*,void* widget,const oui::Rect* r){
    void* object=slot_object(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(widget)));
    void* type=object?fn<void*(*)(void*)>(ObjectClass)(object):nullptr;
    // The object's own class: Label overrides Y (its baseline), as Kabuki notes.
    return type&&r&&prop_set_float(type,object,"X",r->x)&&prop_set_float(type,object,"Y",r->y)&&
        prop_set_float(type,object,"Width",r->w)&&prop_set_float(type,object,"Height",r->h);}
bool engine_set_hold(void*,int ms){
    options_hold_ms.store(std::uint64_t(ms<300?300:ms>1500?1500:ms),std::memory_order_relaxed);return true;}
constexpr oui::Builder::Vt engine_vt{
    engine_add_panel,engine_add_label,engine_set_text,engine_set_visible,engine_set_color,
    engine_screen_w,engine_screen_h,engine_set_capture,engine_send,
    engine_add_image,engine_set_image,engine_set_tint,engine_set_text_style,engine_set_rect,engine_set_hold,engine_send_text,engine_text_width,engine_set_text_valign};
oui::Builder ui_builder(){return oui::Builder{&engine_vt,nullptr};}
void refresh_text(){
    char text[text_limit];
    if(load_feed<text_limit>("text.bin",text,sizeof text)&&std::strcmp(text,last_text)){
        std::snprintf(last_text,sizeof last_text,"%s",text);
        oui::Builder b=ui_builder();
        oui::app::on_text(text,b);
        text_updates.fetch_add(1,std::memory_order_relaxed);}
    // The chat feed, on the same beat, handed over only when it changed.
    static char chat[chat_limit];
    if(load_feed<chat_limit>("chat.bin",chat,sizeof chat)&&std::strcmp(chat,last_chat)){
        std::memcpy(last_chat,chat,std::strlen(chat)+1);
        oui::Builder b=ui_builder();
        oui::app::on_chat(chat,b);}
}
bool try_create(){
    if(create_attempts.fetch_add(1,std::memory_order_relaxed)>=create_attempt_limit)return false;
    // Kabuki-proven layer: our OWN scene added to Application.RootScene with
    // ScreenRenderOverlay - the Game container scene never renders our widgets.
    void* app=app_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(app_handle):nullptr;
    if(!app){note("WIDGET no application instance yet");return false;}
    void* root_scene=nullptr;
    if(!prop_get_object(class_application,app,"RootScene",&root_scene)){note("WIDGET RootScene missing");return false;}
    std::uint32_t root_pin=fn<std::uint32_t(*)(void*,int)>(GcNew)(root_scene,1);
    void* scene=fn<void*(*)(void*,void*)>(ObjectNew)(domain,class_scene);
    if(!scene||!root_pin){note("WIDGET scene allocation failed");return false;}
    fn<void(*)(void*)>(ObjectInit)(scene);
    std::uint32_t scene_pin=fn<std::uint32_t(*)(void*,int)>(GcNew)(scene,1);
    if(!scene_pin){note("WIDGET scene pin failed");return false;}
    int yes=1,no=0;
    if(!prop_set_int(class_scene,scene,"Focusable",no)||
       !prop_set_int(class_scene,scene,"ScreenFixedTransform",yes)||
       !prop_set_int(class_scene,scene,"ScreenRenderOverlay",yes)){
        note("WIDGET scene flags failed");fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);
        fn<void(*)(std::uint32_t)>(GcFree)(root_pin);return false;}
    void* root=nullptr;
    if(!prop_get_object(class_scene,scene,"RootWidget",&root)){note("WIDGET scene RootWidget missing");        fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);fn<void(*)(std::uint32_t)>(GcFree)(root_pin);return false;}
    std::uint32_t root_widget_pin=fn<std::uint32_t(*)(void*,int)>(GcNew)(root,1);
    if(!root_widget_pin){note("WIDGET root widget pin failed");        fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);fn<void(*)(std::uint32_t)>(GcFree)(root_pin);return false;}
    float screen=0;if(!prop_get_float(class_widget,root,"Width",screen)||screen<=1)screen=1920;
    ui_screen_w=screen;ui_screen_h=1080;
    // Handles publish before the app builds: engine_add_* resolves the scene
    // root through scene_root_handle.
    root_scene_handle=root_pin;scene_handle=scene_pin;scene_root_handle=root_widget_pin;

    // The application builds its UI through the oui API; the engine only
    // provides the scene and the Builder.
    oui::Builder builder=ui_builder();
    if(!oui::app::build(builder)){
        note("WIDGET app build refused");
        slots_release(); // anything the half-built UI created is never published
        fn<void(*)(std::uint32_t)>(GcFree)(root_widget_pin);fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);
        fn<void(*)(std::uint32_t)>(GcFree)(root_pin);
        widgets_created.store(-1,std::memory_order_release);
        return false;}
    // Publish the scene. AddScene lives on the runtime class of the root scene
    // object (inherited), exactly like the reference.
    void* root_class=fn<void*(*)(void*)>(ObjectClass)(root_scene);
    Method* add_scene=method_inherited(root_class,"AddScene",1);
    if(!add_scene){note("WIDGET AddScene method missing");
        slots_release();
        fn<void(*)(std::uint32_t)>(GcFree)(root_widget_pin);fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);
        fn<void(*)(std::uint32_t)>(GcFree)(root_pin);
        widgets_created.store(-1,std::memory_order_release);
        return false;}
    void* scene_args[1];scene_args[0]=scene;void* exception=nullptr;bool ok_invoke=false;
    invoke_ex(add_scene,root_scene,scene_args,ok_invoke,&exception);
    if(!ok_invoke){describe_exception("AddScene",exception);note("WIDGET AddScene failed");
        slots_release();
        fn<void(*)(std::uint32_t)>(GcFree)(root_widget_pin);fn<void(*)(std::uint32_t)>(GcFree)(scene_pin);
        fn<void(*)(std::uint32_t)>(GcFree)(root_pin);
        widgets_created.store(-1,std::memory_order_release);
        return false;}
    removal_requested=false;
    bool appended=false;(void)prop_get_bool(class_scene,scene,"IsAppended",&appended);
    widgets_created.store(1,std::memory_order_release);
    note("WIDGET scene added screen=%.0f appended=%d",screen,appended);
    return true;}
// 0 pending (scene removal queued / still appended), 1 done, -1 error.
// The reference tears the whole scene down via RemoveFromSuperScene and polls
// IsAppended across UI callbacks; per-widget RemoveFromParent cannot finish it.
int remove_widgets(){
    void* scene=scene_handle?fn<void*(*)(std::uint32_t)>(GcTarget)(scene_handle):nullptr;
    if(!scene){note("WIDGET removed (no scene)");return scene_handle?-1:1;}
    bool appended=false;
    if(!prop_get_bool(class_scene,scene,"IsAppended",&appended)){note("WIDGET IsAppended unreadable");return 0;}
    if(appended){
        if(!removal_requested){
            Method* remove=method_inherited(class_scene,"RemoveFromSuperScene",0);
            if(!remove){note("WIDGET RemoveFromSuperScene missing");return -1;}
            void* exception=nullptr;bool ok_invoke=false;
            invoke_ex(remove,scene,nullptr,ok_invoke,&exception);
            if(!ok_invoke){describe_exception("RemoveFromSuperScene",exception);return -1;}
            removal_requested=true;note("WIDGET scene removal requested");}
        return 0;} // still appended: next UI callback re-checks
    slots_release();
    fn<void(*)(std::uint32_t)>(GcFree)(scene_root_handle);scene_root_handle=0;
    fn<void(*)(std::uint32_t)>(GcFree)(scene_handle);scene_handle=0;
    fn<void(*)(std::uint32_t)>(GcFree)(root_scene_handle);root_scene_handle=0;
    if(app_handle){fn<void(*)(std::uint32_t)>(GcFree)(app_handle);app_handle=0;}
    note("WIDGET scene removed and handles freed");
    return 1;
}
void update_hook(Object* instance){
    Update prior=original.load(std::memory_order_acquire);if(prior)prior(instance);
    if(!enabled.load(std::memory_order_acquire))return;
    auto tick=updates.fetch_add(1,std::memory_order_relaxed)+1;
    if(!root_found.load(std::memory_order_acquire)&&scene_attempts.load()<3&&(tick==1||tick==61||tick==121))observe_scene();
    if(!draws(request.mode))return;
    // The Update callback's instance IS the Application; pin it once so scene
    // creation can ask it for RootScene (captured before the stop check only
    // while we may still build).
    if(!teardown.load(std::memory_order_acquire)&&!app_handle&&instance)
        app_handle=fn<std::uint32_t(*)(void*,int)>(GcNew)(instance,1);
    // Stop is checked first so no new widgets appear after a stop request, even
    // when creation never succeeded.
    if(teardown.load(std::memory_order_acquire)){
        int state=widget_removed.load(std::memory_order_relaxed);
        // 0: poll every callback (queued removal may take frames). -1 with live
        // scene handles: one bounded retry. 1: done.
        if(state==0){
            int progress=remove_widgets();
            if(progress!=0)widget_removed.store(progress,std::memory_order_release);}
        else if(state==-1&&!cleanup_retry_used&&scene_handle){
            cleanup_retry_used=true;
            widget_removed.store(remove_widgets(),std::memory_order_release);}
        return;}
    if(widgets_created.load(std::memory_order_acquire)<=0){
        if(tick>=create_delay_ticks&&create_attempts.load(std::memory_order_relaxed)<create_attempt_limit){
            if(try_create()&&widgets_created.load()>0)refresh_text();}
        return;}
    if((tick%text_period_ticks)==0)refresh_text();
    oui::Builder builder=ui_builder();
    oui::app::on_tick(tick,builder);
    if(gesture_requested.exchange(false,std::memory_order_acq_rel)){
        oui::app::on_gesture(oui::Gesture::Chord,builder);
        note("GESTURE chords=%u",chords.load());}
#ifndef OVERLAY_APP_LAB
    if(holding.load()&&now_ms()-last_input_ms.load()>hold_idle_ms){
        // Nothing reached us for a while: maybe ShellUI sees no pad without focus. Close.
        release_game("idle");capture.store(false);oui::app::on_gesture(oui::Gesture::Chord,builder);}
#endif
    if(capture.load(std::memory_order_acquire)){
        float x=0,y=0;std::uint32_t bx=stick_x.load(std::memory_order_relaxed),by=stick_y.load(std::memory_order_relaxed);
        std::memcpy(&x,&bx,4);std::memcpy(&y,&by,4);
        oui::app::on_pad(pending_down.exchange(0,std::memory_order_acq_rel),x,y,builder);}
}
void note_share(std::uint64_t at){
    std::uint64_t prior=last_share_at.load(std::memory_order_relaxed);
    unsigned n=share_events.fetch_add(1,std::memory_order_relaxed)+1;
    if(prior&&at>=prior&&at-prior<=350)double_presses.fetch_add(1,std::memory_order_relaxed);
    last_share_at.store(at,std::memory_order_relaxed);
    if(n<=5||n%50==0)note("SHARE n=%u delta=%lldms buttons=%x",n,(long long)(prior?at-prior:0),
        last_buttons.load(std::memory_order_relaxed));
}
PadData pad_hook(int device){
    PadCall prior=pad_original.load(std::memory_order_acquire);
    PadData data{};
    if(prior)data=prior(device);
    if(!input_enabled.load(std::memory_order_acquire))return data;
    pad_polls.fetch_add(1,std::memory_order_relaxed);
    std::uint32_t buttons=data.buttons;
    last_buttons.store(buttons,std::memory_order_relaxed);
    if((buttons&(bit_l3|bit_r3))==(bit_l3|bit_r3)){
        if(!chord_held.exchange(true,std::memory_order_relaxed)){
            chords.fetch_add(1,std::memory_order_relaxed);
            gesture_requested.store(true,std::memory_order_release);}}
    else chord_held.store(false,std::memory_order_relaxed);
    if(buttons&bit_options){
        const std::uint64_t now=now_ms(),since=options_since.load(std::memory_order_relaxed);
        if(!since)options_since.store(now,std::memory_order_relaxed);
        else if(now-since>=options_hold_ms.load(std::memory_order_relaxed)&&!options_fired.exchange(true,std::memory_order_relaxed)){
            chords.fetch_add(1,std::memory_order_relaxed);
            gesture_requested.store(true,std::memory_order_release);}}
    else{options_since.store(0,std::memory_order_relaxed);options_fired.store(false,std::memory_order_relaxed);}
    if(capture.load(std::memory_order_acquire)){
        std::uint32_t down=data.down&~(bit_l3|bit_r3);
        // Held D-pad, Square, L1 and R1 repeat, as in the system's own menus and keyboard:
        // after 350 ms, every 60 ms. Per controller (the hook is called per device).
        {constexpr std::uint32_t repeat=0x1|0x2|0x4|0x8|0x10|0x400|0x800;
         static std::uint64_t held[8][12],last[8][12];
         const int d=device<0?0:device&7;const std::uint64_t now=now_ms();
         if(repeat_reset.exchange(false,std::memory_order_acq_rel)){std::memset(held,0,sizeof held);std::memset(last,0,sizeof last);}
         for(int i=0;i<12;i++){const std::uint32_t bit=1u<<i;if(!(repeat&bit))continue;
             if(!(buttons&bit)){held[d][i]=0;continue;}
             if(!held[d][i]){held[d][i]=last[d][i]=now;continue;}
             if(now-held[d][i]>=350&&now-last[d][i]>=60){last[d][i]=now;down|=bit|oui::app::kPadRepeat;}}}
        if(down){
            last_input_ms.store(now_ms(),std::memory_order_relaxed);
            pending_down.fetch_or(down,std::memory_order_acq_rel);
            // Calibration evidence: which bit each button is (only Cross, L3, R3 are known).
            if(pad_logged.fetch_add(1,std::memory_order_relaxed)<200)note("PAD down=%x",down);}
        std::uint32_t x,y;std::memcpy(&x,&data.lx,4);std::memcpy(&y,&data.ly,4);
        stick_x.store(x,std::memory_order_relaxed);stick_y.store(y,std::memory_order_relaxed);}
    if(holding.load(std::memory_order_acquire)){
        // ShellUI has the controller for our panel: its own menus get a quiet pad (Kabuki
        // swallows these events too). We read the presses above.
        PadData quiet{};quiet.skip=data.skip;return quiet;}
    return data;
}
void share_hook(void* event){
    if(ShareCall prior=share_original.load(std::memory_order_acquire))prior(event);
    if(!input_enabled.load(std::memory_order_acquire))return;
    note_share(now_ms());
}
bool resolve_update_methods(){
    void* pui=image("/system_ex/common_ex/lib/Sce.PlayStation.PUI.dll");
    void* app=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.AppSystem.dll");
    Method* update=method(pui,"Sce.PlayStation.PUI","Application","Update",0);
    find_scene=method(app,"Sce.Vsh.ShellUI.AppSystem","LayerManager","FindContainerSceneByPath",1);
    root_getter=method(pui,"Sce.PlayStation.PUI.UI2","Scene","get_RootWidget",0);
    if(!update||!find_scene||!root_getter||!signature(update,true,0,kind_void)||
       !signature(find_scene,false,1,kind_class)||!signature(root_getter,true,0,kind_class)){
        note("REFUSED required methods/signature missing update=%p find=%p root=%p",update,find_scene,root_getter);return false;}
    if(draws(request.mode)){
        class_application=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI","Application");
        class_scene=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","Scene");
        Method* root_scene_getter=class_application?fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_application,"get_RootScene",0):nullptr;
        class_widget=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","Widget");
        class_panel=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","Panel");
        class_label=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","Label");
        method_text_width=class_label?fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_label,"GetTextWidth",0):nullptr;
        class_font=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","UIFont");
        // Classes are validated before every MethodFromName: a null class is not a
        // safe lookup input in the real runtime, only in our fake.
        if(!class_widget||!class_panel||!class_label||!class_font||!class_application||!class_scene){
            note("REFUSED widget classes missing widget=%p panel=%p label=%p font=%p app=%p scene=%p",
                class_widget,class_panel,class_label,class_font,class_application,class_scene);return false;}
        if(!root_scene_getter||!signature(root_scene_getter,true,0,kind_class)){
            note("REFUSED Application.RootScene signature missing getter=%p",root_scene_getter);return false;}
        method_append=fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_widget,"AppendChild",1);
        method_find=fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_widget,"FindWidgetByName",1);
        Method* font_ctor=fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_font,".ctor",3);
        method_font_ctor=font_ctor;
        class_image=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI.UI2","ImageBox");
        class_asset=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(pui,"Sce.PlayStation.PUI","ImageAsset");
        method_asset_ctor=class_asset?method_taking(class_asset,".ctor","System.String"):nullptr;
        describe_types();
        note("PICTURES image=%p asset=%p ctor=%p",class_image,class_asset,method_asset_ctor);
        Method* remove_scene=fn<Method*(*)(void*,const char*,int)>(MethodFromName)(class_scene,"RemoveFromSuperScene",0);
        if(!method_append||!font_ctor||!remove_scene||
           !signature(method_append,true,1,kind_void)||!signature(font_ctor,true,3,kind_void)||
           !signature(remove_scene,true,0,kind_void)){
            note("REFUSED widget methods/signature missing append=%p find=%p detach=%p font_ctor=%p",
                method_append,method_find,font_ctor);return false;}}
    void* entry=fn<void*(*)(void*)>(CompileMethod)(update);
    note("RESOLVED Update=%p FindContainerSceneByPath=%p RootWidget=%p",entry,find_scene,root_getter);
    if(entry){ // log-only evidence for the hook stage. Never read code bytes:
        // Mono JIT pages here are not data-readable (a memcpy at the entry
        // killed SceShellUI on console, 2026-11-02).
        auto query=fn<ProtectionQuery>(QueryProtection);
        void* lo=nullptr,*hi=nullptr;int prot=0;
        int qrc=query?query(entry,&lo,&hi,&prot):-999;
        note("HOOKDIAG entry=%p qrc=%d prot=%d lo=%p hi=%p",entry,qrc,prot,lo,hi);}
    resolved_update_entry=entry;
    return entry&&now_ms()<request.deadline_ms;
}
void hook_step(const char* text){note("HOOKSTEP %s",text);}
bool prepare_update_hook(void* entry){
    auto query=fn<ProtectionQuery>(QueryProtection);
    note("HOOKSTEP prepare begin");
    if(!prepare_hook(update_hook_store,entry,reinterpret_cast<void*>(&update_hook),query,fn<MprotectCall>(TargetMprotect),fn<MmapCall>(TargetMmap),fn<MunmapCall>(TargetMunmap),hook_step)){
        // prepare_hook copies 16 bytes into .before before it can refuse at the
        // decode step; log them even on refusal, so a mismatched firmware's
        // real prologue is visible instead of guessed at.
        note("PROLOGUE bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            update_hook_store.before[0],update_hook_store.before[1],update_hook_store.before[2],update_hook_store.before[3],
            update_hook_store.before[4],update_hook_store.before[5],update_hook_store.before[6],update_hook_store.before[7],
            update_hook_store.before[8],update_hook_store.before[9],update_hook_store.before[10],update_hook_store.before[11],
            update_hook_store.before[12],update_hook_store.before[13],update_hook_store.before[14],update_hook_store.before[15]);
        note("REFUSED Update alignment, permissions or relocatable prologue");return false;}
    auto length=native_patch_length(update_hook_store.before);
    note("HOOKSTEP prepared len=%zu bytes=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x tramp=%p",
        (std::size_t)length,
        update_hook_store.before[0],update_hook_store.before[1],update_hook_store.before[2],update_hook_store.before[3],
        update_hook_store.before[4],update_hook_store.before[5],update_hook_store.before[6],update_hook_store.before[7],
        update_hook_store.before[8],update_hook_store.before[9],update_hook_store.before[10],update_hook_store.before[11],
        update_hook_store.before[12],update_hook_store.before[13],update_hook_store.before[14],update_hook_store.before[15],
        update_hook_store.trampoline);
    original.store(reinterpret_cast<Update>(update_hook_store.trampoline),std::memory_order_release);
    note("HOOKSTEP install begin");
    if(!install_hook(update_hook_store,query)){note("REFUSED hook installation/protection restore");return false;}
    note("HOOKSTEP installed");
    return true;
}
bool install_pad_hook(){
    void* core=image("/system_ex/common_ex/lib/Sce.PlayStation.Core.dll");
    Method* get_data=method(core,"Sce.PlayStation.Core.Input","GamePad","GetData",1);
    if(!get_data||!signature(get_data,false,1,kind_valuetype)){
        note("REFUSED GamePad.GetData missing for toggle");return false;}
    void* pad_entry=fn<void*(*)(void*)>(CompileMethod)(get_data);
    if(!pad_entry||now_ms()>=request.deadline_ms)return false;
    auto query=fn<ProtectionQuery>(QueryProtection);
    if(!prepare_hook(pad_hook_store,pad_entry,reinterpret_cast<void*>(&pad_hook),query,
                     fn<MprotectCall>(TargetMprotect),fn<MmapCall>(TargetMmap),fn<MunmapCall>(TargetMunmap))){
        note("REFUSED pad hook preparation");return false;}
    pad_original.store(reinterpret_cast<PadCall>(pad_hook_store.trampoline),std::memory_order_release);
    if(!install_hook(pad_hook_store,query)){note("REFUSED pad hook installation");return false;}
    return true;
}
bool resolve_input_methods(){
    void* core=image("/system_ex/common_ex/lib/Sce.PlayStation.Core.dll");
    void* capture=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.CaptureMenu.dll");
    Method* get_data=method(core,"Sce.PlayStation.Core.Input","GamePad","GetData",1);
    Method* on_share=method(capture,"Sce.Vsh.ShellUI.CaptureMenu","EventManager","OnShareButton",1);
    if(!get_data||!on_share||!signature(get_data,false,1,kind_valuetype)||!signature(on_share,false,1,kind_void)){
        note("REFUSED input methods/signature missing get=%p share=%p",get_data,on_share);return false;}
    void* pad_entry=fn<void*(*)(void*)>(CompileMethod)(get_data);
    void* share_entry=fn<void*(*)(void*)>(CompileMethod)(on_share);
    note("RESOLVED GamePad.GetData=%p EventManager.OnShareButton=%p",pad_entry,share_entry);
    if(!pad_entry||!share_entry||now_ms()>=request.deadline_ms)return false;
    auto query=fn<ProtectionQuery>(QueryProtection);
    if(!prepare_hook(pad_hook_store,pad_entry,reinterpret_cast<void*>(&pad_hook),query,fn<MprotectCall>(TargetMprotect),fn<MmapCall>(TargetMmap),fn<MunmapCall>(TargetMunmap),hook_step)||
       !prepare_hook(share_hook_store,share_entry,reinterpret_cast<void*>(&share_hook),query,fn<MprotectCall>(TargetMprotect),fn<MmapCall>(TargetMmap),fn<MunmapCall>(TargetMunmap),hook_step)){
        note("REFUSED input hook preparation");return false;}
    pad_original.store(reinterpret_cast<PadCall>(pad_hook_store.trampoline),std::memory_order_release);
    share_original.store(reinterpret_cast<ShareCall>(share_hook_store.trampoline),std::memory_order_release);
    if(!install_hook(pad_hook_store,query)||!install_hook(share_hook_store,query)){
        note("REFUSED input hook installation");return false;}
    input_enabled.store(true,std::memory_order_release);
    return true;
}
void publish(State state){
    Status s;s.token=request.token;s.at_ms=now_ms();s.state=state;s.updates=updates.load();
    s.scene_attempts=scene_attempts.load();s.game_found=game_found.load();s.root_found=root_found.load();
    s.hook_installed=(update_hook_store.was_installed?1:0)+(pad_hook_store.was_installed?1:0)+(share_hook_store.was_installed?1:0);
    s.hook_removed=(update_hook_store.was_installed&&!update_hook_store.installed?1:0)+
        (pad_hook_store.was_installed&&!pad_hook_store.installed?1:0)+
        (share_hook_store.was_installed&&!share_hook_store.installed?1:0);
    s.widgets_created=widgets_created.load();s.widget_removed=widget_removed.load();
    s.create_attempts=create_attempts.load();s.text_updates=text_updates.load();
    s.pad_polls=pad_polls.load();s.share_events=share_events.load();s.chords=chords.load();
    s.double_presses=double_presses.load();s.last_buttons=last_buttons.load();
    (void)write_file(worker_dir,"status.bin",s);
}
// Mode::AudioTest only: no Mono, no hooking, nothing shared with the rest
// of this file. Just sceAudioOut from inside SceShellUI's own process, to
// see whether it plays on, or is muted the moment a game takes the
// console's audio/video ownership the way the app's own AudioOut is
// (measured 2026-11-22: the app's sound stops the instant AvControl hands
// AudioOut/VideoOut to another pid, and comes back when it regains focus).
State run_audio_test(){
    publish(State::Observing);
    const auto init=fn<AudioOutInitCall>(AudioOutInit);
    const auto open=fn<AudioOutOpenCall>(AudioOutOpen);
    const auto output=fn<AudioOutOutputCall>(AudioOutOutput);
    const auto close=fn<AudioOutCloseCall>(AudioOutClose);
    const int init_rc=init();
    note("AUDIOTEST init rc=0x%08x",unsigned(init_rc));
    if(init_rc!=0&&init_rc!=static_cast<int>(0x8026000e)){publish(State::Failed);return State::Failed;}
    const int handle=open(0xff,0,0,256,48000,1);
    note("AUDIOTEST open rc=0x%08x",unsigned(handle));
    if(handle<0){publish(State::Failed);return State::Failed;}
    alignas(64) std::int16_t grain[256*2];
    double phase=0.0;constexpr double freq=880.0,rate=48000.0;
    int writes=0,errors=0;
    const std::uint64_t until=now_ms()+60000;
    while(now_ms()<until){
        for(int i=0;i<256;i++){
            const std::int16_t s=std::int16_t(std::sin(phase)*12000.0);
            grain[i*2]=s;grain[i*2+1]=s;phase+=2.0*3.14159265358979*freq/rate;
        }
        const int rc=output(handle,grain);++writes;
        if(rc<0){++errors;if(errors<=5||errors%100==0)note("AUDIOTEST write #%d rc=0x%08x",writes,unsigned(rc));}
        if(writes%200==0){note("AUDIOTEST writes=%d errors=%d",writes,errors);publish(State::Observing);}
        std::uint64_t stop=0;if(read_file(worker_dir,"stop.bin",stop)&&stop==request.token)break;
    }
    output(handle,nullptr);close(handle);
    note("AUDIOTEST done writes=%d errors=%d",writes,errors);
    const State result=errors==0&&writes>0?State::Passed:State::Failed;
    publish(result);return result;
}
// Mode::AudioRelay only: like run_audio_test(), but the source is real voice
// PCM piped from the app over a loopback socket (platform/ps5/audio_relay.hpp),
// not a generated tone. Runs for as long as that connection stays up (the
// app closing it, or stop.bin, end it cleanly), bounded by a safety ceiling.
// The core's key (src/core_key.h): 64 hex characters the core writes next to the app
// (/app0 on the app side). Whether SceShellUI sees that real path is one of the things this
// lab measures; the key is never logged, only whether and from where it was read.
bool read_core_key(char out[64],bool verbose){
    static constexpr const char* paths[]={
        // ShellUI's /data is not the one the app and the core see (measured 2026-11-23: ENOENT on
        // /data/homebrew/PPSA99073/control.key), but its /user/data is the real partition (the
        // overlay's own log and chat files live there). The edition's own folder only: the CI
        // refuses any binary that names the stock one.
        "/user/data/homebrew/PPSA99073/control.key",
        "/data/homebrew/PPSA99073/control.key",
        "/app0/control.key",
    };
    for(const char* p:paths){
        FILE* f=std::fopen(p,"rb");
        if(!f){if(verbose)note("AUDIODIRECT key %s open errno=%d",p,errno);continue;}
        char buf[65]{};const std::size_t got=std::fread(buf,1,64,f);
        const int extra=std::fgetc(f);std::fclose(f);
        if(verbose)note("AUDIODIRECT key %s read %zu bytes trailing=%s",p,got,extra==EOF?"none":"some");
        if(got==64){std::memcpy(out,buf,64);return true;}
    }
    return false;
}
// Connects to the core's tap listener (src/voice_audio.c VAU_TAP_PORT) and sends the key.
int connect_tap(const char key[64]){
    constexpr std::uint16_t tap_port=9044;
    const int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return -1;
#ifdef SO_NOSIGPIPE
    {const int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof one);} // never let a dead peer SIGPIPE SceShellUI
#endif
    // Without TCP_NODELAY, Nagle holds each 512-byte mic grain until the core's delayed ACK (~100 ms) lets it go whenever the
    // core has nothing to send back (nobody talking): the mic reached the core in 100 ms bursts, which its 80 ms lag guard
    // cut to 40% and replayed at double speed ("silence, then the sentence sped up"; measured 2026-11-23, 143872 samples
    // dropped in one 5 s window while the worker was reading the mic at exactly real time).
    {const int one=1;setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one);}
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(tap_port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof a)!=0){close(fd);return -1;}
    // The key, then "TAP2" in the same write: a v2 client is never replaced by an older worker's reconnects.
    char hello[68];std::memcpy(hello,key,64);std::memcpy(hello+64,"TAP2",4);
    if(send(fd,hello,sizeof hello,0)!=ssize_t(sizeof hello)){close(fd);return -1;}
    const int flags=fcntl(fd,F_GETFL,0);fcntl(fd,F_SETFL,flags|O_NONBLOCK);
    return fd;
}
// Mode::AudioRelay, preferred path: the voice PCM comes straight from the core's tap
// listener, so nothing depends on the app, which the console suspends when a real game
// launches (measured 2026-11-23: the app-fed relay died at that instant). The output is
// this worker's own sceAudioOut inside SceShellUI, which keeps playing under a game's AV
// focus. Reconnects by itself (core restart, key change) once a second.
State run_audio_direct(char key[64]){
    publish(State::Observing);
    const auto init=fn<AudioOutInitCall>(AudioOutInit);
    const auto open=fn<AudioOutOpenCall>(AudioOutOpen);
    const auto output=fn<AudioOutOutputCall>(AudioOutOutput);
    const auto close_out=fn<AudioOutCloseCall>(AudioOutClose);
    const int init_rc=init();
    note("AUDIODIRECT init rc=0x%08x",unsigned(init_rc));
    if(init_rc!=0&&init_rc!=static_cast<int>(0x8026000e)){publish(State::Failed);return State::Failed;}
    const int handle=open(0xff,0,0,256,48000,1);
    note("AUDIODIRECT open rc=0x%08x",unsigned(handle));
    if(handle<0){publish(State::Failed);return State::Failed;}
    // The microphone, captured inside ShellUI (type 0, 48 kHz, S16 mono, grain 256, the app's own arguments):
    // the console kills the app when a game launches, and the app was the only thing that captured it. It is
    // opened only while the core says the app is not delivering one (the marker file `tap-mic`, which the
    // core creates and removes), so it never competes with the app's own capture in the call screen or the
    // PS menu; an empty file `no-mic` next to worker.log turns the whole thing off.
    int mic=-1;std::uint64_t mic_reads=0,mic_errors=0,mic_sent=0,next_mic_check=0,mic_open_fails=0;
    int mic_peak=0;double mic_sq=0;std::uint64_t mic_n=0;
    auto file_exists=[&](const char* name){
        char fp[256];if(!path(fp,sizeof fp,worker_dir,name))return false;
        FILE* ff=std::fopen(fp,"rb");if(!ff)return false;std::fclose(ff);return true;};
    auto open_mic=[&]()->int{
        if(!(request.functions[AudioInOpen]&&request.functions[AudioInInput]&&request.functions[AudioInClose])){
            if(mic_open_fails++==0)note("AUDIOIN functions MISSING (libSceAudioIn not loaded in ShellUI?)");
            return -1;}
        int user=-1;
        if(request.functions[UserGetForegroundUser]){
            int u=-1;const int rc=fn<UserForegroundCall>(UserGetForegroundUser)(&u);
            if(rc==0)user=u;}
        const int users[2]={user,0xff};
        for(int u:users){
            if(u<0)continue;
            const int h=fn<AudioInOpenCall>(AudioInOpen)(u,0,0,256,48000,1);
            if(h>=0){note("AUDIOIN open user=0x%x handle=0x%x",unsigned(u),unsigned(h));return h;}
            if(mic_open_fails<3||mic_open_fails%120==0)note("AUDIOIN open user=0x%x rc=0x%08x",unsigned(u),unsigned(h));
        }
        ++mic_open_fails;return -1;
    };
    alignas(64) std::int16_t mic_grain[256];
    int fd=-1;std::uint64_t next_try=0,last_data=0,connects=0;
    static std::uint8_t pending[32768];std::size_t pending_len=0; // ~170 ms of stereo, off the thread stack
    alignas(64) std::int16_t grain[256*2];
    int writes=0,errors=0;std::uint64_t recv_bytes=0;
    const std::uint64_t began=now_ms();
    const std::uint64_t until=began+86300000; // 24 h, under request.deadline_ms (parent.cpp); the core relaunches a dead worker
    auto play_grain=[&]{
        const int rc=output(handle,grain);++writes;
        if(rc<0){++errors;if(errors<=5||errors%100==0)note("AUDIODIRECT write #%d rc=0x%08x",writes,unsigned(rc));}
        if(writes%200==0){
            note("AUDIODIRECT writes=%d errors=%d recv_bytes=%llu connects=%llu",writes,errors,
                 static_cast<unsigned long long>(recv_bytes),static_cast<unsigned long long>(connects));
            publish(State::Observing);}
    };
    // One grain of playback and one grain of mic per pass, never a burst of either: AudioOut and AudioIn each
    // block for one 5.33 ms grain, and the old "play everything that arrived" loop spent ~20 ms in playback per
    // core frame, so the mic was read at ~30% of real time and reached the core crackling and cut
    // (measured 2026-11-23: 28 KB/s of the 96 KB/s a 48 kHz S16 mono mic makes).
    std::uint64_t last_stop_check=0;
    std::uint64_t pass_max=0,slow_passes=0,send_eagain=0,dropped_bytes=0,compressed=0; // timing evidence, logged with the mic level
    bool compressing=false;
    std::uint64_t last_beat=0,fail_streak=0;
    // Playback queue marks (bytes of stereo S16): the console's audio clock runs 0.5-1.3 % slower than the
    // core's 20 ms mix clock (measured 2026-11-23: the queue sat at its 32 KB cap and dropped 2-3 grains a
    // second, each drop a click), so above kHigh the next grains are time-compressed by 1.6 % until the queue
    // is under kLow again; kHardCap only guards against a stall.
    constexpr std::size_t kHardCap=16384,kHigh=8192,kLow=6144;
    while(now_ms()<until){
        const std::uint64_t now=now_ms();
        const std::uint64_t pass_began=now;
        if(now-last_stop_check>1000){ // an empty marker file `stop-audio` ends this worker (it holds the lock until then)
            last_stop_check=now;
            char sp[256];FILE* sf=path(sp,sizeof sp,worker_dir,"stop-audio")?std::fopen(sp,"rb"):nullptr;
            if(sf){std::fclose(sf);note("AUDIODIRECT stop-audio marker found: ending");break;}
        }
        if(now-last_beat>2000){ // a heartbeat the core looks at (src/overlay.c): a stale one gets the worker launched again
            last_beat=now;
            char hp[256];FILE* hf=path(hp,sizeof hp,worker_dir,"audio-alive")?std::fopen(hp,"wb"):nullptr;
            if(hf){std::fputc('1',hf);std::fclose(hf);}
        }
        if(now>=next_mic_check){ // follow the core's `tap-mic` marker: the mic is ours only while the app has none
            next_mic_check=now+(mic>=0?500:1000);
            const bool wanted=file_exists("tap-mic")&&!file_exists("no-mic");
            if(wanted&&mic<0)mic=open_mic();
            else if(!wanted&&mic>=0){fn<AudioInCloseCall>(AudioInClose)(mic);mic=-1;note("AUDIOIN closed (the app delivers its own mic again)");}
        }
        if(fd<0&&now>=next_try){
            // The core may not be running (app closed): retry every second at first, then every 5 s, and
            // keep the log quiet (the first few failures, then one in 60).
            next_try=now+(fail_streak<10?1000:5000);
            char current[64];
            const bool verbose=fail_streak<3||fail_streak%60==0;
            if(read_core_key(current,verbose))std::memcpy(key,current,64); // the key is per boot: re-read it
            fd=connect_tap(key);
            ++connects;
            if(fd>=0){fail_streak=0;note("AUDIODIRECT tap connect ok (attempt %llu)",static_cast<unsigned long long>(connects));}
            else{++fail_streak;if(verbose)note("AUDIODIRECT tap connect failed (streak %llu)",static_cast<unsigned long long>(fail_streak));}
            pending_len=0;
        }
        if(fd>=0){
            std::uint8_t buf[4096];
            const ssize_t got=recv(fd,buf,sizeof buf,MSG_DONTWAIT);
            if(got==0||(got<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)){
                note("AUDIODIRECT tap closed rc=%zd errno=%d",got,errno);close(fd);fd=-1;next_try=now+500;
            } else if(got>0){
                recv_bytes+=std::uint64_t(got);last_data=now;
                if(pending_len+std::size_t(got)>kHardCap){ // far behind: the oldest whole grains go, frames stay aligned
                    std::size_t drop=pending_len+std::size_t(got)-kHardCap;
                    drop=(drop+sizeof grain-1)/sizeof grain*sizeof grain;
                    if(drop>pending_len)drop=pending_len;
                    dropped_bytes+=drop;
                    std::memmove(pending,pending+drop,pending_len-drop);pending_len-=drop;
                }
                std::memcpy(pending+pending_len,buf,std::size_t(got));pending_len+=std::size_t(got);
            }
        }
        bool busy=false;
        if(pending_len>=sizeof grain){
            if(pending_len>kHigh)compressing=true;else if(pending_len<kLow)compressing=false;
            if(compressing&&pending_len>=261*4){
                // 260 input frames become the 256 of this grain (linear interpolation, +1.6 % speed: below hearing).
                alignas(64) std::int16_t src[264*2];
                std::memcpy(src,pending,261*4);
                for(int j=0;j<256;j++){
                    const double pos=double(j)*260.0/256.0;const int i0=int(pos);const double fr=pos-double(i0);
                    for(int c=0;c<2;c++){
                        const double a=src[i0*2+c],b=src[(i0+1)*2+c];
                        grain[j*2+c]=std::int16_t(a+(b-a)*fr);
                    }
                }
                std::memmove(pending,pending+260*4,pending_len-260*4);pending_len-=260*4;++compressed;
            } else {
                std::memcpy(grain,pending,sizeof grain);
                std::memmove(pending,pending+sizeof grain,pending_len-sizeof grain);pending_len-=sizeof grain;
            }
            play_grain();busy=true;
        } else if(pending_len>0&&now-last_data>40){
            // Idle: the last partial grain of a burst of speech is padded with silence and played
            // rather than left to be glued onto the start of the next one.
            std::memset(grain,0,sizeof grain);std::memcpy(grain,pending,pending_len);pending_len=0;play_grain();busy=true;
        }
        if(mic>=0){ // blocks for one 5.33 ms grain (usually already waiting after the playback call)
            const int rc=fn<AudioInInputCall>(AudioInInput)(mic,mic_grain);++mic_reads;
            if(rc<0){
                ++mic_errors;
                if(mic_errors<=5||mic_errors%200==0){
                    note("AUDIOIN read #%llu rc=0x%08x",static_cast<unsigned long long>(mic_reads),unsigned(rc));
                }
                usleep(5000);
            } else {
                busy=true;
                for(int i=0;i<256;i++){const int a=mic_grain[i]<0?-int(mic_grain[i]):int(mic_grain[i]);
                    if(a>mic_peak)mic_peak=a;mic_sq+=double(mic_grain[i])*double(mic_grain[i]);}
                mic_n+=256;
                // Forward the grain to the core over the same socket (the core only uses it while the app
                // is not delivering its own mic). Best effort: never blocks, a lost grain is a 5 ms gap.
                if(fd>=0){
                    const ssize_t sent=send(fd,mic_grain,sizeof mic_grain,MSG_DONTWAIT);
                    if(sent>0&&sent<ssize_t(sizeof mic_grain))note("AUDIOIN partial send %zd",sent);
                    else if(sent>0)mic_sent+=std::uint64_t(sent);
                    else if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK))++send_eagain;
                }
            }
            if(mic_reads%200==0){
                const double rms=mic_n?std::sqrt(mic_sq/double(mic_n)):0.0;
                note("AUDIOIN reads=%llu errors=%llu peak=%d rms=%d sent=%llu passmax=%llums slow=%llu eagain=%llu dropped=%llu comp=%llu pending=%zu",
                     static_cast<unsigned long long>(mic_reads),static_cast<unsigned long long>(mic_errors),mic_peak,int(rms),
                     static_cast<unsigned long long>(mic_sent),static_cast<unsigned long long>(pass_max),
                     static_cast<unsigned long long>(slow_passes),static_cast<unsigned long long>(send_eagain),
                     static_cast<unsigned long long>(dropped_bytes),static_cast<unsigned long long>(compressed),pending_len);
                mic_peak=0;mic_sq=0;mic_n=0;pass_max=0;}
        }
        {const std::uint64_t took=now_ms()-pass_began;if(took>pass_max)pass_max=took;if(took>15)++slow_passes;}
        if(!busy)usleep(fd>=0?4000:(mic>=0?4000:100000)); // nothing to play or capture right now; do not spin
    }
    if(fd>=0)close(fd);
    if(mic>=0)fn<AudioInCloseCall>(AudioInClose)(mic);
    output(handle,nullptr);close_out(handle);
    note("AUDIODIRECT done writes=%d errors=%d recv_bytes=%llu elapsed_ms=%llu",writes,errors,
         static_cast<unsigned long long>(recv_bytes),static_cast<unsigned long long>(now_ms()-began));
    const State result=writes>0?State::Passed:State::Failed;
    publish(result);return result;
}
State run_audio_relay(){
    {char key[64]{};
     // Always the direct path now: the core may not be running yet (the worker is launched by the core
     // itself, or by hand), and run_audio_direct() re-reads the key at every connection attempt.
     (void)read_core_key(key,true);
     return run_audio_direct(key);}
    publish(State::Observing);
    // Fixed and known to both ends at compile time (app/src/platform/ps5/
    // audio_relay.hpp hardcodes the same value): no file handoff, which is
    // what kept failing (measured 2026-11-22, several different ways,
    // across both /data/... and /user/data/...: this worker's sandbox and
    // the app's do not agree on a single path one can write and the other
    // read). Loopback-only, single-user console: an unauthenticated local
    // connection is an acceptable trade for not depending on that agreement.
    constexpr std::uint16_t port=9043;
    const int fd=socket(AF_INET,SOCK_STREAM,0);
    note("AUDIORELAY socket fd=%d errno=%d",fd,errno);
    if(fd<0){publish(State::Failed);return State::Failed;}
    sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    const int connect_rc=connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof a);
    note("AUDIORELAY connect port=%u rc=%d errno=%d",unsigned(port),connect_rc,errno);
    if(connect_rc!=0){close(fd);publish(State::Failed);return State::Failed;}
    const int flags=fcntl(fd,F_GETFL,0);fcntl(fd,F_SETFL,flags|O_NONBLOCK);

    const auto init=fn<AudioOutInitCall>(AudioOutInit);
    const auto open=fn<AudioOutOpenCall>(AudioOutOpen);
    const auto output=fn<AudioOutOutputCall>(AudioOutOutput);
    const auto close_out=fn<AudioOutCloseCall>(AudioOutClose);
    const int init_rc=init();
    note("AUDIORELAY init rc=0x%08x",unsigned(init_rc));
    if(init_rc!=0&&init_rc!=static_cast<int>(0x8026000e)){close(fd);publish(State::Failed);return State::Failed;}
    const int handle=open(0xff,0,0,256,48000,1);
    note("AUDIORELAY open rc=0x%08x",unsigned(handle));
    if(handle<0){close(fd);publish(State::Failed);return State::Failed;}

    std::uint8_t pending[4096];std::size_t pending_len=0;
    alignas(64) std::int16_t grain[256*2];
    int writes=0,errors=0;std::uint64_t recv_bytes=0;
    const std::uint64_t began=now_ms();
    const std::uint64_t until=began+570000; // under the loader's deadline
    bool link_closed=false;
    const char* reason="until elapsed";
    // Not stop.bin: measured 2026-11-22 that the external loader process
    // (outside ShellUI, forked by parent.cpp's main()) reliably dies within
    // ~150 ms of starting, for every mode, AudioTest included -- it just
    // never mattered before, because run_audio_test()'s loop never checks
    // stop.bin at all and keeps going regardless, independently, inside
    // ShellUI. This loop used to check it too, and that is what was cutting
    // every relay off almost immediately, long before the app's own side
    // even finished dialing in. Left unsolved: why the loader dies that
    // fast; nothing here or in parent.cpp sends it a signal that early.
    while(!link_closed&&now_ms()<until){
        std::uint8_t buf[4096];
        const ssize_t got=recv(fd,buf,sizeof buf,MSG_DONTWAIT);
        if(got==0||(got<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)){
            note("AUDIORELAY connection closed rc=%zd errno=%d",got,errno);link_closed=true;reason="recv closed/error";break;}
        if(got>0){
            recv_bytes+=std::uint64_t(got);
            std::size_t at=0;
            while(at<std::size_t(got)){
                const std::size_t take=std::min(std::size_t(got)-at,sizeof pending-pending_len);
                std::memcpy(pending+pending_len,buf+at,take);pending_len+=take;at+=take;
                while(pending_len>=sizeof grain){
                    std::memcpy(grain,pending,sizeof grain);
                    std::memmove(pending,pending+sizeof grain,pending_len-sizeof grain);pending_len-=sizeof grain;
                    const int rc=output(handle,grain);++writes;
                    if(rc<0){++errors;if(errors<=5||errors%100==0)note("AUDIORELAY write #%d rc=0x%08x",writes,unsigned(rc));}
                    if(writes%200==0){
                        note("AUDIORELAY writes=%d errors=%d recv_bytes=%llu",writes,errors,
                             static_cast<unsigned long long>(recv_bytes));
                        publish(State::Observing);}
                }
            }
        } else {
            usleep(2000); // nothing waiting right now; do not spin
        }
    }
    output(handle,nullptr);close_out(handle);close(fd);
    note("AUDIORELAY done writes=%d errors=%d recv_bytes=%llu elapsed_ms=%llu reason=%s",writes,errors,
         static_cast<unsigned long long>(recv_bytes),static_cast<unsigned long long>(now_ms()-began),reason);
    const State result=writes>0?State::Passed:State::Failed;
    publish(result);return result;
}
// Mode::PartyProbe (lab, no Mono, no hooking, no audio): a client of the PS5's party voice service, written from what
// the console's own libSceProprietaryVoiceChatHelper.native.sprx (13.60) and the party daemon (NPXS40109) do.
// The helper itself is not usable from ShellUI (its file does not load there, and it refuses unless a sysctl says the
// process is a title), so this talks to the service the way the helper does, through libSceIpmi, already loaded:
//   cfg = default config (O1lQ2+do5r4), then the name "ScePartyIpcService", +0x1c = 1, +0x20 = 1, +0x28 = +0x30 = 0x4000;
//   client = an object built in place in a 0x1000-byte buffer (0zsTiDhM0nU(&client,&cfg,0,buffer)); its vtable:
//   [0] destroy, [2] connect, [3] disconnect (0x80020010 while busy), [11] invoke-sync, [17] abort.
//   connect(&9,4,&result): session type 9 is the proprietary voice chat helper's.
//   invoke-sync(method,in*,nIn,&result,out*,nOut): 0x510000 register(int id), 0x510001 unregister, 0x510002 set(0|1) =
//   "my own voice chat is active", 0x510003 get(out int) = 0 or 1 (rc 0x816d0506 until a set(1); the daemon's own
//   errors are 0x816da5xx).
// The steps (one word each) come from party-steps.txt next to worker.log and are re-read once a second: a changed file
// runs again, a word starting with # is ignored, and a file named stop-party ends the probe. No file: the safe default.
//   ipmi-open  ipmi-register[=id|game|shell]  ipmi-set0  ipmi-set1  ipmi-get  ipmi-watchN  ipmi-unregister  ipmi-close  bigapp
//   sleepN  sysctl:a.b.c.d  open:/path  load:/path   (the last three only look, or load a library on request)
// Whatever is open or registered is unregistered and closed at the end of every run, never left behind.
struct IpmiBuf{const void* ptr;std::size_t size;};
using LoadStartCall=int(*)(const char*,std::size_t,const void*,unsigned,const void*,int*);
using SysctlCall=int(*)(const int*,unsigned,void*,std::size_t*,const void*,std::size_t);
using IpmiConfigInitCall=void(*)(void*);
using IpmiCreateCall=int(*)(void**,const void*,void*,void*);
using IpmiConnectCall=int(*)(void*,const void*,std::size_t,int*);
using IpmiCall=int(*)(void*);
using IpmiInvokeCall=int(*)(void*,unsigned,const IpmiBuf*,unsigned,int*,const IpmiBuf*,unsigned);
constexpr int ipmi_busy=static_cast<int>(0x80020010);
alignas(64) unsigned char party_client_memory[0x1000];
alignas(64) unsigned char party_config[0x200];
State run_party_probe(){
    publish(State::Observing);
    note("PARTY start pid=%d shell_app=0x%x",int(getpid()),unsigned(request.shell_app));
    const auto config_init=fn<IpmiConfigInitCall>(IpmiConfigInit);
    const auto create=fn<IpmiCreateCall>(IpmiClientCreate);
    if(!config_init||!create){note("PARTY refused: the libSceIpmi client functions were not resolved");publish(State::Failed);return State::Failed;}
    void* client=nullptr;bool registered=false;int problems=0,runs=0;
    auto stop_requested=[&]{
        char fp[256];if(!path(fp,sizeof fp,worker_dir,"stop-party"))return false;
        FILE* f=std::fopen(fp,"rb");if(!f)return false;std::fclose(f);return true;};
    // The running game's app id (the id its own helper would register), -1 when there is none or it cannot be asked.
    auto big_app=[&]()->int{return request.functions[RunningBigApp]?fn<int(*)()>(RunningBigApp)():-1;};
    // A vtable entry of the open client, or null when anything about it looks wrong.
    auto slot=[&](unsigned index)->void*{
        if(!client)return nullptr;
        void** vt=*static_cast<void***>(client);
        if(!vt||!address(reinterpret_cast<std::uintptr_t>(vt)))return nullptr;
        void* f=vt[index];
        return address(reinterpret_cast<std::uintptr_t>(f))?f:nullptr;};
    auto invoke=[&](unsigned method,const IpmiBuf* in,unsigned in_count,const IpmiBuf* out,unsigned out_count,int& result)->int{
        void* f=slot(11);
        result=-1;
        if(!f)return -1;
        return reinterpret_cast<IpmiInvokeCall>(f)(client,method,in,in_count,&result,out,out_count);};
    // The helper's own teardown: disconnect until it stops being busy, a forced abort if it never does, then destroy.
    auto close_client=[&]{
        if(!client)return;
        if(void* disconnect=slot(3)){
            int rc=0;
            for(int i=0;i<11;++i){rc=reinterpret_cast<IpmiCall>(disconnect)(client);if(rc!=ipmi_busy)break;usleep(2000);}
            note("PARTY close disconnect rc=0x%08x",unsigned(rc));
            if(rc==ipmi_busy){if(void* abort_call=slot(17)){const int arc=reinterpret_cast<IpmiCall>(abort_call)(client);note("PARTY close abort rc=0x%08x",unsigned(arc));}}
        }
        if(void* destroy=slot(0))(void)reinterpret_cast<IpmiCall>(destroy)(client);
        note("PARTY close done");
        client=nullptr;registered=false;};
    auto run_steps=[&](char* text){
        char* cursor=text;int steps=0;++runs;
        for(;;){
            while(*cursor==' '||*cursor=='\n'||*cursor=='\r'||*cursor=='\t')++cursor;
            if(!*cursor||steps>=40)break;
            char* word=cursor;
            while(*cursor&&*cursor!=' '&&*cursor!='\n'&&*cursor!='\r'&&*cursor!='\t')++cursor;
            if(*cursor)*cursor++=0;
            if(word[0]=='#')continue;
            ++steps;
            if(stop_requested()){note("PARTY stop-party marker: leaving this run");break;}
            if(!std::strcmp(word,"ipmi-open")){
                if(client){note("PARTY ipmi-open: a client is already open");++problems;continue;}
                std::memset(party_config,0,sizeof party_config);
                std::memset(party_client_memory,0,sizeof party_client_memory);
                config_init(party_config);
                std::memcpy(party_config,"ScePartyIpcService",19);
                const std::int32_t pair[2]={1,1};
                std::memcpy(party_config+0x1c,pair,sizeof pair);
                const std::uint64_t buffer_size=0x4000;
                std::memcpy(party_config+0x28,&buffer_size,sizeof buffer_size);
                std::memcpy(party_config+0x30,&buffer_size,sizeof buffer_size);
                void* created=nullptr;
                const int rc=create(&created,party_config,nullptr,party_client_memory);
                note("PARTY ipmi-open create rc=0x%08x client=%p",unsigned(rc),created);
                if(rc!=0||!created){++problems;continue;}
                client=created;
                void* connect_fn=slot(2);
                if(!connect_fn||!slot(3)||!slot(11)||!slot(0)){note("PARTY ipmi-open: the client's vtable looks wrong, closing it");close_client();++problems;continue;}
                const int session_type=9;int accepted=-1;
                const int crc=reinterpret_cast<IpmiConnectCall>(connect_fn)(client,&session_type,sizeof session_type,&accepted);
                note("PARTY ipmi-open connect rc=0x%08x result=0x%08x",unsigned(crc),unsigned(accepted));
                if(crc<0||accepted<0){close_client();++problems;continue;}
            } else if(!std::strncmp(word,"ipmi-register",13)){
                if(!client){note("PARTY %s: no client open",word);++problems;continue;}
                int id=request.shell_app;
                if(const char* eq=std::strchr(word,'=')){
                    if(!std::strcmp(eq+1,"game"))id=big_app();
                    else if(!std::strcmp(eq+1,"shell"))id=request.shell_app;
                    else id=static_cast<int>(std::strtol(eq+1,nullptr,0));}
                const IpmiBuf in{&id,sizeof id};int result=-1;
                const int rc=invoke(0x510000,&in,1,nullptr,0,result);
                note("PARTY ipmi-register id=0x%x rc=0x%08x result=0x%08x",unsigned(id),unsigned(rc),unsigned(result));
                if(rc==0&&result==0)registered=true;else ++problems;
            } else if(!std::strcmp(word,"ipmi-unregister")){
                if(!client){note("PARTY ipmi-unregister: no client open");++problems;continue;}
                int result=-1;
                const int rc=invoke(0x510001,nullptr,0,nullptr,0,result);
                note("PARTY ipmi-unregister rc=0x%08x result=0x%08x",unsigned(rc),unsigned(result));
                if(rc==0&&result==0)registered=false;else ++problems;
            } else if(!std::strcmp(word,"ipmi-set0")||!std::strcmp(word,"ipmi-set1")){
                if(!client){note("PARTY %s: no client open",word);++problems;continue;}
                int value=word[8]=='1'?1:0;
                const IpmiBuf in{&value,sizeof value};int result=-1;
                const int rc=invoke(0x510002,&in,1,nullptr,0,result);
                note("PARTY ipmi-set%d rc=0x%08x result=0x%08x",value,unsigned(rc),unsigned(result));
                if(rc!=0||result!=0)++problems;
            } else if(!std::strcmp(word,"ipmi-get")){
                if(!client){note("PARTY ipmi-get: no client open");++problems;continue;}
                int value=-99;const IpmiBuf out{&value,sizeof value};int result=-1;
                const int rc=invoke(0x510003,nullptr,0,&out,1,result);
                // 0x816d0506 before any set(1) is the daemon's normal answer, not a problem.
                note("PARTY ipmi-get rc=0x%08x result=0x%08x value=%d",unsigned(rc),unsigned(result),value);
                if(rc!=0)++problems;
            } else if(!std::strncmp(word,"ipmi-watch",10)){
                // One get per second for N seconds (at most 180), logging only the changes and a line every 15 s.
                if(!client){note("PARTY ipmi-watch: no client open");++problems;continue;}
                const int seconds=std::atoi(word+10);
                int last_rc=-1000,last_result=-1000,last_value=-1000;
                note("PARTY watch for %d s, big_app=0x%x",seconds,unsigned(big_app()));
                for(int s=0;s<seconds&&s<180&&!stop_requested()&&now_ms()+8000<request.deadline_ms;++s){
                    int value=-99;const IpmiBuf out{&value,sizeof value};int result=-1;
                    const int rc=invoke(0x510003,nullptr,0,&out,1,result);
                    if(rc!=last_rc||result!=last_result||value!=last_value||s%15==0){
                        note("PARTY watch t=%ds rc=0x%08x result=0x%08x value=%d big_app=0x%x",s,unsigned(rc),unsigned(result),value,unsigned(big_app()));
                        last_rc=rc;last_result=result;last_value=value;}
                    usleep(1000000);
                }
            } else if(!std::strcmp(word,"bigapp")){
                note("PARTY bigapp id=0x%x",unsigned(big_app()));
            } else if(!std::strcmp(word,"ipmi-close")){
                close_client();
            } else if(!std::strncmp(word,"sleep",5)){
                const int seconds=std::atoi(word+5);
                note("PARTY sleep %d s",seconds);
                for(int s=0;s<seconds&&s<300&&!stop_requested()&&now_ms()+8000<request.deadline_ms;++s)usleep(1000000);
            } else if(!std::strncmp(word,"sysctl:",7)){
                const auto sysctl_call=fn<SysctlCall>(KernelSysctl);
                if(!sysctl_call){note("PARTY sysctl was not resolved");++problems;continue;}
                int mib[6]{};unsigned count=0;const char* at=word+7;
                while(*at&&count<6){char* stop=nullptr;mib[count++]=static_cast<int>(std::strtol(at,&stop,10));if(stop==at)break;at=(*stop=='.')?stop+1:stop;}
                unsigned char data[32]{};std::size_t length=sizeof data;
                const int rc=sysctl_call(mib,count,data,&length,nullptr,0);
                std::uint32_t d[4]{};std::memcpy(d,data,sizeof d);
                note("PARTY sysctl %s rc=%d len=%zu d0=0x%08x d1=0x%08x d2=0x%08x d3=0x%08x",word+7,rc,length,unsigned(d[0]),unsigned(d[1]),unsigned(d[2]),unsigned(d[3]));
            } else if(!std::strncmp(word,"open:",5)){
                const int fd=open(word+5,O_RDONLY);const int err=errno;
                note("PARTY open %s -> %d errno=%d",word+5,fd,fd<0?err:0);
                if(fd>=0)close(fd);
            } else if(!std::strncmp(word,"load:",5)){
                const auto load=fn<LoadStartCall>(KernelLoadStartModule);
                if(!load){note("PARTY load was not resolved");++problems;continue;}
                int res=0;const int handle=load(word+5,0,nullptr,0,nullptr,&res);
                note("PARTY load %s -> 0x%08x res=0x%08x",word+5,unsigned(handle),unsigned(res));
            } else {
                note("PARTY step '%s' unknown, skipped",word);++problems;
            }
        }
        if(registered&&client){
            int result=-1;
            const int rc=invoke(0x510001,nullptr,0,nullptr,0,result);
            note("PARTY cleanup unregister rc=0x%08x result=0x%08x",unsigned(rc),unsigned(result));
        }
        close_client();};
    char words[512]{},last[512]{};
    auto read_steps=[&](char* out)->bool{
        out[0]=0;
        char fp[256];if(!path(fp,sizeof fp,worker_dir,"party-steps.txt"))return false;
        FILE* f=std::fopen(fp,"rb");if(!f)return false;
        const std::size_t got=std::fread(out,1,511,f);out[got]=0;std::fclose(f);return got>0;};
    if(!read_steps(words))std::snprintf(words,sizeof words,"ipmi-open ipmi-register ipmi-get ipmi-unregister ipmi-close");
    std::memcpy(last,words,sizeof last);
    note("PARTY steps: %s",words);
    run_steps(words);
    const std::uint64_t until=request.deadline_ms>6000?request.deadline_ms-6000:0;
    while(now_ms()<until&&!stop_requested()){
        usleep(1000000);
        char next[512]{};
        if(read_steps(next)&&std::strcmp(next,last)!=0){
            std::memcpy(last,next,sizeof last);
            note("PARTY steps changed: %s",next);
            run_steps(next);
        }
    }
    close_client();
    note("PARTY done runs=%d problems=%d",runs,problems);
    const State result=problems==0?State::Passed:State::Failed;
    publish(result);return result;
}
// Mode::SceneProbe (lab, read-only Mono reflection, no hooking, no IPMI, no audio): walks the .NET metadata of the
// Control Center's voice tile types (Sce.Vsh.ShellUI.VoiceChat.dll) and dumps their fields, methods and properties
// to worker.log so a later run can forge a SessionEventData and invoke OnDaemonEvent to raise the native tile with
// our own content. Nothing is called that touches the party service or any other system daemon; only the managed
// classes already present in ShellUI are introspected. If the assembly is not loaded in ShellUI, AssemblyOpen reads
// it off disk and returns an image that is as introspectable as the running one for metadata purposes.
void probe_fields(void* klass,const char* cls){
    if(!klass){note("PROBE fields %s: class is null",cls);return;}
    void* iter=nullptr;
    for(int i=0;i<256;++i){
        void* f=fn<void*(*)(void*,void**)>(ClassFields)(klass,&iter);if(!f)break;
        void* ft=fn<void*(*)(void*)>(FieldType)(f);
        const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
        const char* ftype=ft?fn<const char*(*)(void*)>(TypeName)(ft):nullptr;
        unsigned offset=fn<unsigned(*)(void*)>(FieldOffset)(f);
        int kind=ft?fn<int(*)(void*)>(TypeKind)(ft):-1;
        note("PROBE field %s.%s : %s (kind %d) @%u",cls,fname?fname:"?",ftype?ftype:"?",kind,offset);}
}
void probe_methods(void* klass,const char* cls){
    if(!klass){note("PROBE methods %s: class is null",cls);return;}
    void* iter=nullptr;
    for(int i=0;i<256;++i){
        void* m=fn<void*(*)(void*,void**)>(ClassMethods)(klass,&iter);if(!m)break;
        const char* n=fn<const char*(*)(void*)>(MethodName)(m);
        void* sig=fn<void*(*)(void*)>(MethodSignature)(m);
        int params=sig?int(fn<unsigned(*)(void*)>(SignatureCount)(sig)):-1;
        int is_inst=sig?fn<int(*)(void*)>(SignatureInstance)(sig):-1;
        void* ret=sig?fn<void*(*)(void*)>(SignatureReturn)(sig):nullptr;
        const char* rt=ret?fn<const char*(*)(void*)>(TypeName)(ret):nullptr;
        // v4: also log parameter type names so the metadata names classes that live in other assemblies
        // (mono_signature_get_params returns one MonoType per call and advances iter, NULL ends it).
        char pbuf[480];pbuf[0]='\0';int plen=0;
        if(sig){
            void* piter=nullptr;
            for(int j=0;j<16;++j){
                void* pt=fn<void*(*)(void*,void**)>(SignatureParams)(sig,&piter);if(!pt)break;
                const char* pn=fn<const char*(*)(void*)>(TypeName)(pt);
                int w=std::snprintf(pbuf+plen,sizeof(pbuf)-plen,"%s%s",plen?",":"",pn?pn:"?");
                if(w<0||plen+w>=int(sizeof(pbuf))){plen=int(sizeof(pbuf))-1;pbuf[plen]='\0';break;}
                plen+=w;}}
        note("PROBE method %s.%s(%s) params=%d instance=%d returns=%s",cls,n?n:"?",pbuf,params,is_inst,rt?rt:"?");}
}
State run_scene_probe(){
    publish(State::Observing);
    note("PROBE start pid=%d shell_app=0x%x build=0x%016llx",int(getpid()),unsigned(request.shell_app),
         (unsigned long long)OVERLAY_BUILD);
    domain=fn<void*(*)()>(RootDomain)();
    if(!domain){note("PROBE refused: Mono root domain missing");publish(State::Failed);return State::Failed;}
    void* thread=fn<void*(*)(void*)>(ThreadAttach)(domain);
    if(!thread){note("PROBE refused: Mono thread attach failed");publish(State::Failed);return State::Failed;}
    // The assembly that owns VoiceChatModule, SessionEventData and the daemon event plumbing of the Control Center.
    void* img_voice=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.VoiceChat.dll");
    note("PROBE image Sce.Vsh.ShellUI.VoiceChat.dll=%p",img_voice);
    if(img_voice){
        struct Ent{const char* ns;const char* name;};
        // Probe v3: v2 showed Session is the Go Live streamer record, not a voice-chat participant. The participant
        // data for the tile with pseudos and mic state goes through the CHANNEL path (_OnVoiceChatChannelEvent and
        // ConvertChannelEventDataToJObject). v3 walks that path: ChannelEvent/ChannelEventData, their likely member
        // types, and MemberAddress (Session.streamer references it). Still metadata-only; no Mono method invoked.
        static const Ent entries[]={
            {"Sce.Vsh.ShellUI.VoiceChat","VoiceChatModule"},
            // Channel path — the voice-chat participants tile.
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelEvent"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelEventData"},
            {"Sce.Vsh.ShellUI.VoiceChat","Channel"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelMember"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelParticipant"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelUser"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelState"},
            {"Sce.Vsh.ShellUI.VoiceChat","ChannelInfo"},
            {"Sce.Vsh.ShellUI.VoiceChat","MemberAddress"},
            // Known types kept as a cross-check between probe runs.
            {"Sce.Vsh.ShellUI.VoiceChat","Session"},
            {"Sce.Vsh.ShellUI.VoiceChat","EventHeader"}};
        for(const auto& e:entries){
            void* k=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img_voice,e.ns,e.name);
            note("PROBE class %s.%s=%p",e.ns,e.name,k);
            if(k){probe_fields(k,e.name);probe_methods(k,e.name);describe_properties(k,e.name);}}}
    // Probe v5: resolve the three mystery types (VoiceChatModuleEventHandler, SceVoiceChat{Daemon,Channel}EventHandler)
    // by walking their holder methods' parameter MonoType and calling ClassFromType on it, which cuts through the
    // IpcTypes namespace / nested-class name problem that made ClassFromName return 0 in v2-v4. Then dump each
    // resolved class via probe_fields / probe_methods so its Invoke signature appears in the log. Still metadata-only.
    if(img_voice){
        void* vcm=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img_voice,"Sce.Vsh.ShellUI.VoiceChat","VoiceChatModule");
        struct Pick{const char* method;int count;int param;const char* label;};
        static const Pick picks[]={
            {"RegisterVoiceChatModuleEventHandler",2,1,"VoiceChatModuleEventHandler"},
            {"sceVoiceChatRegisterDaemonEventHandler",2,0,"SceVoiceChatDaemonEventHandler"},
            {"sceVoiceChatRegisterChannelEventHandler",2,0,"SceVoiceChatChannelEventHandler"}};
        for(const auto& p:picks){
            void* m=vcm?fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm,p.method,p.count):nullptr;
            void* sig=m?fn<void*(*)(void*)>(MethodSignature)(m):nullptr;
            void* pt=nullptr;
            if(sig){void* it=nullptr;for(int k=0;k<=p.param;++k){pt=fn<void*(*)(void*,void**)>(SignatureParams)(sig,&it);if(!pt)break;}}
            void* kls=pt?fn<void*(*)(void*)>(ClassFromType)(pt):nullptr;
            note("PROBE resolve %s via %s(param %d)=%p",p.label,p.method,p.param,kls);
            if(kls){probe_fields(kls,p.label);probe_methods(kls,p.label);}}
    }
    // Probe v6: read the live VoiceChatModule.Instance, dump its voiceChatModuleEventHandlerDic class fields, then
    // walk that Dictionary's keys to collect every event name the RN voice tile actually listens for. This is the
    // last metadata gap before the tile code: given a key, forging the tile reduces to calling the matching
    // handler with our own (string, JObject). The walk uses only read-only runtime_invoke on managed getters;
    // no handler is called, nothing is registered or unregistered, no system service is touched.
    if(img_voice){
        void* vcm=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img_voice,"Sce.Vsh.ShellUI.VoiceChat","VoiceChatModule");
        void* mget=vcm?fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm,"GetInstance",0):nullptr;
        void* ex=nullptr;
        void* inst=mget?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mget,nullptr,nullptr,&ex):nullptr;
        note("PROBE live VoiceChatModule.GetInstance()=%p ex=%p",inst,ex);
        if(inst){
            // Field voiceChatModuleEventHandlerDic sits at @16 of the instance (v2/v4 dumps).
            void* dict=*(void**)((char*)inst+16);
            note("PROBE live voiceChatModuleEventHandlerDic=%p",dict);
            if(dict){
                void* dclass=fn<void*(*)(void*)>(ObjectClass)(dict);
                const char* dname=dclass?fn<const char*(*)(void*)>(ClassNameGet)(dclass):nullptr;
                note("PROBE dict class=%p name=%s",dclass,dname?dname:"?");
                if(dclass){probe_fields(dclass,"Dictionary");}
                // Call get_Count() on the dict to publish the count, then walk via get_Keys().GetEnumerator().
                void* mcount=dclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(dclass,"get_Count",0):nullptr;
                if(mcount){
                    ex=nullptr;
                    void* boxed=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcount,dict,nullptr,&ex);
                    int cnt=boxed?*(int*)fn<void*(*)(void*)>(ObjectUnbox)(boxed):-1;
                    note("PROBE dict count=%d ex=%p",cnt,ex);}
                void* mkeys=dclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(dclass,"get_Keys",0):nullptr;
                ex=nullptr;
                void* keys=mkeys?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mkeys,dict,nullptr,&ex):nullptr;
                note("PROBE dict.get_Keys()=%p ex=%p",keys,ex);
                if(keys){
                    void* kclass=fn<void*(*)(void*)>(ObjectClass)(keys);
                    void* menum=kclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(kclass,"GetEnumerator",0):nullptr;
                    ex=nullptr;
                    void* en=menum?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(menum,keys,nullptr,&ex):nullptr;
                    note("PROBE keys.GetEnumerator()=%p ex=%p",en,ex);
                    if(en){
                        // Enumerator is a value type; its instance methods take an unboxed `this` pointer.
                        void* ec=fn<void*(*)(void*)>(ObjectClass)(en);
                        void* mnext=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"MoveNext",0):nullptr;
                        void* mcurr=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"get_Current",0):nullptr;
                        void* ethis=fn<void*(*)(void*)>(ObjectUnbox)(en);
                        note("PROBE enum class=%p MoveNext=%p get_Current=%p this=%p",ec,mnext,mcurr,ethis);
                        if(mnext&&mcurr&&ethis){
                            for(int i=0;i<64;++i){
                                ex=nullptr;
                                void* bnext=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mnext,ethis,nullptr,&ex);
                                int alive=bnext?*(int*)fn<void*(*)(void*)>(ObjectUnbox)(bnext):0;
                                if(!alive){note("PROBE walk end at i=%d",i);break;}
                                ex=nullptr;
                                void* key=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcurr,ethis,nullptr,&ex);
                                // MonoString layout: 0=vtable, 8=sync, 16=length(int32), 20=UTF-16 chars.
                                if(key){
                                    int klen=*(int*)((char*)key+16);
                                    const unsigned short* ku=(const unsigned short*)((char*)key+20);
                                    char buf[256];int w=0;
                                    for(int j=0;j<klen&&j<int(sizeof(buf))-1;++j){unsigned short c=ku[j];buf[w++]=(c<0x80)?char(c):'?';}
                                    buf[w]='\0';
                                    note("PROBE event key[%d]=\"%s\"",i,buf);
                                } else { note("PROBE key[%d]=null",i); }}
                        }
                    }
                }
            }
        }
    }
    // Context: a few neighbouring assemblies that back the Control Center voice tile's JavaScript bridge.
    static const char* const neighbours[]={
        "/system_ex/common_ex/lib/Sce.Vsh.PartyCommon.dll",
        "/system_ex/common_ex/lib/Sce.Vsh.Np.SessionService.dll"};
    for(const char* p:neighbours){void* im=image(p);note("PROBE image %s=%p",p,im);}
    // Stay alive for a bounded window so the loader sees the Observing state and the stop file can cut us short.
    const std::uint64_t deadline=request.deadline_ms>6000?request.deadline_ms-6000:now_ms()+20000;
    while(now_ms()<deadline){
        std::uint64_t stop=0;
        if(read_file(worker_dir,"stop.bin",stop)&&stop==request.token)break;
        publish(State::Observing);
        usleep(500000);}
    fn<void(*)(void*)>(ThreadDetach)(thread);
    note("PROBE done");
    publish(State::Passed);return State::Passed;
}
// Tile observation helpers (lab, read-only): log the object graph reachable from the delegate targets that sit in
// VoiceChatModule's handler dictionary and, when a PartyStatusMonitor shows up, its live state. Only managed field
// reads on reference-typed fields plus a few getters; nothing is written, no handler is called.
void tile_log_string_set(void* coll,const char* label){
    if(!coll){note("TILE set %s = null",label);return;}
    void* c=fn<void*(*)(void*)>(ObjectClass)(coll);
    void* mcount=c?fn<void*(*)(void*,const char*,int)>(MethodFromName)(c,"get_Count",0):nullptr;
    void* ex=nullptr;
    void* b=mcount?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcount,coll,nullptr,&ex):nullptr;
    note("TILE set %s count=%d ex=%p",label,b?*(int*)fn<void*(*)(void*)>(ObjectUnbox)(b):-1,ex);
    void* menum=c?fn<void*(*)(void*,const char*,int)>(MethodFromName)(c,"GetEnumerator",0):nullptr;
    ex=nullptr;
    void* en=menum?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(menum,coll,nullptr,&ex):nullptr;
    void* ec=en?fn<void*(*)(void*)>(ObjectClass)(en):nullptr;
    void* mnext=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"MoveNext",0):nullptr;
    void* mcurr=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"get_Current",0):nullptr;
    void* ethis=en?fn<void*(*)(void*)>(ObjectUnbox)(en):nullptr;
    if(!(mnext&&mcurr&&ethis))return;
    for(int i=0;i<32;++i){
        ex=nullptr;
        void* bn=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mnext,ethis,nullptr,&ex);
        if(!bn||!*(int*)fn<void*(*)(void*)>(ObjectUnbox)(bn))break;
        ex=nullptr;
        void* s=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcurr,ethis,nullptr,&ex);
        if(!s)continue;
        int slen=*(int*)((char*)s+16);
        const unsigned short* su=(const unsigned short*)((char*)s+20);
        char buf[128];int w=0;
        for(int j=0;j<slen&&j<int(sizeof(buf))-1;++j)buf[w++]=(su[j]<0x80)?char(su[j]):'?';
        buf[w]='\0';
        note("TILE set %s[%d]=\"%s\"",label,i,buf);}
}
void tile_graph(void* obj,const char* path,int depth,int& budget){
    if(!obj||budget<=0)return;
    --budget;
    void* k=fn<void*(*)(void*)>(ObjectClass)(obj);
    const char* cn=k?fn<const char*(*)(void*)>(ClassNameGet)(k):nullptr;
    note("TILE graph %s : %s",path,cn?cn:"?");
    if(!cn)return;
    if(!std::strcmp(cn,"PartyStatusMonitor")){
        note("TILE PSM m_isInParty=%d m_userId=%d",int(*((unsigned char*)obj+32)),*(int*)((char*)obj+36));
        tile_log_string_set(*(void**)((char*)obj+24),"PSM.m_joinedTargetChannels");
        return;}
    if(depth<=0||std::strchr(cn,'`'))return;
    for(void* walk=k;walk;walk=fn<void*(*)(void*)>(ClassParent)(walk)){
        void* iter=nullptr;
        for(int i=0;i<64;++i){
            void* f=fn<void*(*)(void*,void**)>(ClassFields)(walk,&iter);if(!f)break;
            void* ft=fn<void*(*)(void*)>(FieldType)(f);
            const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
            const char* ftype=ft?fn<const char*(*)(void*)>(TypeName)(ft):nullptr;
            unsigned off=fn<unsigned(*)(void*)>(FieldOffset)(f);
            int kind=ft?fn<int(*)(void*)>(TypeKind)(ft):-1;
            if(off<16||off>4096)continue;                        // static fields report small offsets
            if(kind!=18&&kind!=21&&kind!=28)continue;            // reference-typed fields only
            if(ftype&&(!std::strncmp(ftype,"System.Nullable",15)||std::strstr(ftype,"KeyValuePair")))continue;
            void* child=*(void**)((char*)obj+off);
            if(!child)continue;
            char np[192];std::snprintf(np,sizeof np,"%s.%s",path,fname?fname:"?");
            tile_graph(child,np,depth-1,budget);}}
}
void tile_observe(void* inst,const char* label){
    note("TILE obs %s begin",label);
    void* dict=*(void**)((char*)inst+16);
    void* dclass=dict?fn<void*(*)(void*)>(ObjectClass)(dict):nullptr;
    void* mitem=dclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(dclass,"get_Item",1):nullptr;
    static const char* const keys[]={"voiceChatChannelEvent","voiceChatDaemonEvent"};
    for(const char* kn:keys){
        void* key=fn<void*(*)(void*,const char*)>(StringNew)(domain,kn);
        void* a[1]={key};void* ex=nullptr;
        void* h=mitem?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mitem,dict,a,&ex):nullptr;
        if(!h){note("TILE obs %s: no handler",kn);continue;}
        void* mt=nullptr;
        for(void* w=fn<void*(*)(void*)>(ObjectClass)(h);w&&!mt;w=fn<void*(*)(void*)>(ClassParent)(w))
            mt=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"get_Target",0);
        ex=nullptr;
        void* tgt=mt?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mt,h,nullptr,&ex):nullptr;
        note("TILE obs %s handler=%p target=%p ex=%p",kn,h,tgt,ex);
        int budget=120;char p[96];std::snprintf(p,sizeof p,"%s.target",kn);
        tile_graph(tgt,p,4,budget);}
    note("TILE obs %s end",label);
}
// Read-only structural dump of a managed object (lab): every instance field with its value, recursing into reference
// fields. Arrays are only measured (length), never indexed, and nothing is invoked: reference fields hold either null or
// a valid object, so ObjectClass on them is safe; no pointer is followed that the metadata does not mark as a reference.
[[maybe_unused]] void tile_dump(void* obj,const char* path_,int depth,int& budget,bool strings_only=false){
    if(!obj||budget<=0)return;
    --budget;
    void* k=fn<void*(*)(void*)>(ObjectClass)(obj);
    const char* cn=k?fn<const char*(*)(void*)>(ClassNameGet)(k):nullptr;
    if(cn&&!std::strcmp(cn,"String")){
        int slen=*(int*)((char*)obj+16);const unsigned short* su=(const unsigned short*)((char*)obj+20);
        char buf[72];int w=0;for(int j=0;j<slen&&j<int(sizeof buf)-1;++j)buf[w++]=(su[j]<0x80)?char(su[j]):'?';buf[w]='\0';
        note("TILE dump %s = string \"%s\"",path_,buf);return;}
    if(!strings_only)note("TILE dump %s : %s",path_,cn?cn:"?");
    if(!k)return;
    for(void* walk=k;walk;walk=fn<void*(*)(void*)>(ClassParent)(walk)){
        void* iter=nullptr;
        for(int i=0;i<64;++i){
            void* f=fn<void*(*)(void*,void**)>(ClassFields)(walk,&iter);if(!f)break;
            void* ft=fn<void*(*)(void*)>(FieldType)(f);
            const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
            const char* ftype=ft?fn<const char*(*)(void*)>(TypeName)(ft):nullptr;
            unsigned off=fn<unsigned(*)(void*)>(FieldOffset)(f);
            int kind=ft?fn<int(*)(void*)>(TypeKind)(ft):-1;
            if(off<16||off>4096)continue;                          // static / literal fields report small offsets
            const char* nm=fname?fname:"?";
            if(strings_only){
                // identity hunt: only reference fields, never delegates / weak references / event handlers
                if(kind!=18&&kind!=21&&kind!=28)continue;
                if(ftype&&(std::strstr(ftype,"Delegate")||std::strstr(ftype,"Handler")||std::strstr(ftype,"WeakReference")||std::strstr(ftype,"Action")||std::strstr(ftype,"Func")))continue;}
            switch(kind){
            case 2:case 4:case 5:note("TILE dump %s.%s = %d (%s)",path_,nm,int(*((unsigned char*)obj+off)),ftype?ftype:"?");break;
            case 6:case 7:note("TILE dump %s.%s = %d (%s)",path_,nm,int(*(unsigned short*)((char*)obj+off)),ftype?ftype:"?");break;
            case 8:case 9:note("TILE dump %s.%s = %d (%s)",path_,nm,*(int*)((char*)obj+off),ftype?ftype:"?");break;
            case 10:case 11:case 24:note("TILE dump %s.%s = 0x%llx (%s)",path_,nm,(unsigned long long)*(std::uint64_t*)((char*)obj+off),ftype?ftype:"?");break;
            case 29:{void* arr=*(void**)((char*)obj+off);
                note("TILE dump %s.%s = array %p len=%lld (%s)",path_,nm,arr,arr?(long long)*(std::uint64_t*)((char*)arr+24):-1LL,ftype?ftype:"?");break;}
            case 18:case 21:case 28:{void* child=*(void**)((char*)obj+off);
                if(!child){note("TILE dump %s.%s = null (%s)",path_,nm,ftype?ftype:"?");break;}
                if(ftype&&(std::strstr(ftype,"KeyValuePair")||!std::strncmp(ftype,"System.Nullable",15))){note("TILE dump %s.%s = (skipped %s)",path_,nm,ftype);break;}
                char np[192];std::snprintf(np,sizeof np,"%s.%s",path_,nm);
                if(depth>0)tile_dump(child,np,depth-1,budget,strings_only);
                else if(!strings_only)note("TILE dump %s = %p (%s, depth limit)",np,child,ftype?ftype:"?");
                break;}
            default:break;}}}
}
// Lists what GCCallBackList.GCHandleDict (Dictionary<object,object>, 88 entries seen) holds, through its own managed
// getters (get_Keys / get_Values, GetEnumerator, MoveNext, get_Current: read-only, nothing registered or removed), and
// returns the live ReactNative VoiceChatModule when an entry IS one or is a delegate whose Target is one.
void* tile_enum_callbacks(void* dict,void* rnk,void** list=nullptr,int* count=nullptr,int cap=0){
    void* found=nullptr;
    void* dc=dict?fn<void*(*)(void*)>(ObjectClass)(dict):nullptr;
    static const char* const getters[]={"get_Keys","get_Values"};
    for(const char* g:getters){
        void* mg=dc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(dc,g,0):nullptr;
        void* ex=nullptr;
        void* coll=mg?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mg,dict,nullptr,&ex):nullptr;
        note("TILE cb %s coll=%p ex=%p",g,coll,ex);
        void* cc=coll?fn<void*(*)(void*)>(ObjectClass)(coll):nullptr;
        void* menum=cc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(cc,"GetEnumerator",0):nullptr;
        ex=nullptr;
        void* en=menum?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(menum,coll,nullptr,&ex):nullptr;
        void* ec=en?fn<void*(*)(void*)>(ObjectClass)(en):nullptr;
        void* mnext=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"MoveNext",0):nullptr;
        void* mcurr=ec?fn<void*(*)(void*,const char*,int)>(MethodFromName)(ec,"get_Current",0):nullptr;
        void* ethis=en?fn<void*(*)(void*)>(ObjectUnbox)(en):nullptr;
        if(!(mnext&&mcurr&&ethis)){note("TILE cb %s: enumerator unavailable",g);continue;}
        for(int i=0;i<128;++i){
            ex=nullptr;
            void* bn=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mnext,ethis,nullptr,&ex);
            if(!bn||!*(int*)fn<void*(*)(void*)>(ObjectUnbox)(bn))break;
            ex=nullptr;
            void* e=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcurr,ethis,nullptr,&ex);
            if(!e)continue;
            void* ek=fn<void*(*)(void*)>(ObjectClass)(e);
            const char* en_=ek?fn<const char*(*)(void*)>(ClassNameGet)(ek):nullptr;
            void* mt=nullptr;
            for(void* w=ek;w&&!mt;w=fn<void*(*)(void*)>(ClassParent)(w))
                mt=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"get_Target",0);
            void* tgt=nullptr;
            if(mt){ex=nullptr;tgt=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mt,e,nullptr,&ex);}
            void* tk=tgt?fn<void*(*)(void*)>(ObjectClass)(tgt):nullptr;
            const char* tn=tk?fn<const char*(*)(void*)>(ClassNameGet)(tk):nullptr;
            (void)en_;(void)tn;
            void* cand=(rnk&&ek==rnk)?e:((rnk&&tk==rnk)?tgt:nullptr);
            if(cand){
                if(!found)found=cand;
                if(list&&count){bool seen=false;for(int s=0;s<*count;++s)if(list[s]==cand)seen=true;
                    if(!seen&&*count<cap)list[(*count)++]=cand;}}}
    }
    return found;
}
void tile_log_tostring(void* o,const char* label){
    void* k=o?fn<void*(*)(void*)>(ObjectClass)(o):nullptr;
    void* mts=nullptr;
    for(void* w=k;w&&!mts;w=fn<void*(*)(void*)>(ClassParent)(w))
        mts=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"ToString",0);
    void* ex2=nullptr;
    void* s=mts?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mts,o,nullptr,&ex2):nullptr;
    if(!s){note("TILE RN %s: no ToString (%p)",label,o);return;}
    int slen=*(int*)((char*)s+16);const unsigned short* su=(const unsigned short*)((char*)s+20);
    if(slen>900)slen=900;
    char line[208];int w=0;
    for(int j=0;j<slen;++j){
        unsigned short c=su[j];
        if(c=='\n'||c=='\r'||w>=200){if(w){line[w]='\0';note("TILE RN %s: %s",label,line);w=0;}if(c=='\n'||c=='\r')continue;}
        line[w++]=(c>=0x20&&c<0x7f)?char(c):'?';}
    if(w){line[w]='\0';note("TILE RN %s: %s",label,line);}
}
void* tile_find_method(void* klass,const char* name,int count,const char* first_param);
void* tile_get_context(void* inst){
    void* mctx=nullptr;
    for(void* w=fn<void*(*)(void*)>(ObjectClass)(inst);w&&!mctx;w=fn<void*(*)(void*)>(ClassParent)(w))
        mctx=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"get_Context",0);
    void* ex=nullptr;
    return mctx?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mctx,inst,nullptr,&ex):nullptr;
}
// Managed path (no native struct, no raw pointer): ConvertJsonStringToJObject(string) is the module's own text->JObject
// helper (the native Convert* methods call it with the struct's dataJsonString; 10 guessed native layouts all failed, and
// the method bodies are not readable here: the image carries precompiled code with 1-byte IL stubs). The module also has
// onUserDataEvent(int, string, JObject). Conversion alone is always done and logged; the single onUserDataEvent call
// happens only if the marker file tile-emit exists, and the marker is deleted right away so it cannot repeat.
void tile_rn_event(void* inst,void* rnk,const char* json,const char* evt_name,bool emit){
    if(!rnk||!inst)return;
    void* m=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,"ConvertJsonStringToJObject",1);
    void* js=fn<void*(*)(void*,const char*)>(StringNew)(domain,json);
    void* a1[1]={js};void* ex=nullptr;
    void* jo=m?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m,inst,a1,&ex):nullptr;
    note("TILE RN ConvertJsonStringToJObject -> %p ex=%p",jo,ex);
    if(jo)tile_log_tostring(jo,"converted");
    if(ex)tile_log_tostring(ex,"convert exception");
    // The module's own way to reach JavaScript: its base class gives get_Context() (ReactContext), and the framework helper
    // ReactNative.Vsh.Common.EventEmitterUtility.emitDeviceEvent(ReactContext, string, object) emits a device event. The JS
    // event names are literals of the shell assembly (voiceChatChannelEvent, voiceChatDaemonEvent, ..., partySessionEvent
    // VshNMVoiceChat, ...). No native struct, no raw pointer: only managed objects.
    void* ctx=tile_get_context(inst);
    void* cimg=image("/system_ex/common_ex/lib/ReactNative.Vsh.Common.dll");
    void* eu=cimg?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(cimg,"ReactNative.Vsh.Common","EventEmitterUtility"):nullptr;
    void* me=eu?tile_find_method(eu,"emitDeviceEvent",3,"ReactNative.Bridge.ReactContext"):nullptr;
    note("TILE RN context=%p EventEmitterUtility=%p emitDeviceEvent=%p",ctx,eu,me);
    if(!emit){note("TILE RN emit skipped (no tile-emit marker)");return;}
    if(!jo){note("TILE RN emit refused: no JObject");return;}
    if(!ctx||!me){note("TILE RN emit refused: no context or emitter");return;}
    void* name=fn<void*(*)(void*,const char*)>(StringNew)(domain,evt_name);
    void* a3[3]={ctx,name,jo};
    ex=nullptr;
    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(me,nullptr,a3,&ex);
    note("TILE RN emitDeviceEvent(ctx,\"%s\",jobject) invoked ex=%p",evt_name,ex);
    if(ex)tile_log_tostring(ex,"emit exception");
}
void* tile_find_method(void* klass,const char* name,int count,const char* first_param){
    void* iter=nullptr;
    for(int i=0;i<512;++i){
        void* m=fn<void*(*)(void*,void**)>(ClassMethods)(klass,&iter);if(!m)break;
        const char* n=fn<const char*(*)(void*)>(MethodName)(m);
        if(!n||std::strcmp(n,name))continue;
        void* sig=fn<void*(*)(void*)>(MethodSignature)(m);if(!sig)continue;
        if(int(fn<unsigned(*)(void*)>(SignatureCount)(sig))!=count)continue;
        void* it=nullptr;void* pt=fn<void*(*)(void*,void**)>(SignatureParams)(sig,&it);
        const char* pn=pt?fn<const char*(*)(void*)>(TypeName)(pt):nullptr;
        if(first_param&&(!pn||std::strcmp(pn,first_param)))continue;
        return m;}
    return nullptr;
}
// Build A (read-only): log the JavaScript-bridge surface of a ReactContext — every method its class and
// base classes expose whose name hints at reaching JavaScript (GetJavaScriptModule, the JS Executor,
// Call/Invoke/Eval/RunScript...). Logs only, invokes nothing: this finds the door to run our own JS
// (ensureActionCardHost/addActionCard) inside the Control Center, with no PSN and no native Discord.
void tile_dump_js_bridge(void* ctx){
    if(!ctx)return;
    for(void* w=fn<void*(*)(void*)>(ObjectClass)(ctx);w;w=fn<void*(*)(void*)>(ClassParent)(w)){
        const char* cn=fn<const char*(*)(void*)>(ClassNameGet)(w);
        void* iter=nullptr;
        for(int i=0;i<1024;++i){
            void* m=fn<void*(*)(void*,void**)>(ClassMethods)(w,&iter);if(!m)break;
            const char* n=fn<const char*(*)(void*)>(MethodName)(m);if(!n)continue;
            if(!(std::strstr(n,"Java")||std::strstr(n,"JS")||std::strstr(n,"Script")||std::strstr(n,"Module")||
                 std::strstr(n,"Executor")||std::strstr(n,"Call")||std::strstr(n,"Eval")||std::strstr(n,"Run")||
                 std::strstr(n,"Catalyst")||std::strstr(n,"Bridge")||std::strstr(n,"Invoke")))continue;
            void* sig=fn<void*(*)(void*)>(MethodSignature)(m);
            unsigned pc=sig?fn<unsigned(*)(void*)>(SignatureCount)(sig):0u;
            const char* p0="";
            if(sig&&pc){void* it=nullptr;void* pt=fn<void*(*)(void*,void**)>(SignatureParams)(sig,&it);
                if(pt)p0=fn<const char*(*)(void*)>(TypeName)(pt);}
            note("TILE JSBRIDGE %s::%s(%u) p0=%s",cn?cn:"?",n,pc,p0?p0:"");
        }
    }
}
// Ground-truth native event: instead of guessing the layout, let the runtime build it. A managed
// IpcTypes.SceVoiceChat<Kind>Event (nested type, found through mono_class_get_nested_types) gets its dataJsonString set,
// Marshal.StructureToPtr writes it into unmanaged memory exactly as the module's own marshalling expects, the pure
// Convert<Kind>EventDataToJObject verifies it (logged), and only with `emit` the module's own _OnVoiceChat<Kind>Event is
// invoked on that pointer (marker file, one-shot). Never reads or writes memory we did not allocate through Marshal.
[[maybe_unused]] void tile_rn_native(void* inst,void* rnk,void* rn,const char* json,const char* evt_name,bool emit){
    if(!inst||!rnk||!rn)return;
    const char* p=std::strstr(evt_name,"voiceChat");
    if(!p){note("TILE NATIVE: unusable event name");return;}
    char kind[32]{};{const char* a=p+9;const char* e=std::strstr(a,"Event");std::size_t n=e?std::size_t(e-a):std::strlen(a);if(n>=sizeof kind)n=sizeof kind-1;std::memcpy(kind,a,n);}
    if(!request.functions[MonoNestedTypes]||!request.functions[MonoClassImage]){note("TILE NATIVE: Mono exports missing");return;}
    void* ipc=fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(rn,"ReactNative.Modules.ShellUI.VoiceChat","IpcTypes");
    char want[64];std::snprintf(want,sizeof want,"SceVoiceChat%sEvent",kind);
    void* evk=nullptr;
    if(ipc){void* it=nullptr;
        for(int i=0;i<64;++i){
            void* nk=fn<void*(*)(void*,void**)>(MonoNestedTypes)(ipc,&it);if(!nk)break;
            const char* nn=fn<const char*(*)(void*)>(ClassNameGet)(nk);
            if(nn&&!std::strcmp(nn,want)){evk=nk;break;}}}
    note("TILE NATIVE IpcTypes=%p %s=%p",ipc,want,evk);
    if(!evk)return;
    void* js=fn<void*(*)(void*,const char*)>(StringNew)(domain,json);
    void* corlib=fn<void*(*)(void*)>(MonoClassImage)(fn<void*(*)(void*)>(ObjectClass)(js));
    void* mk=corlib?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(corlib,"System.Runtime.InteropServices","Marshal"):nullptr;
    void* m_alloc=mk?tile_find_method(mk,"AllocHGlobal",1,"System.Int32"):nullptr;
    void* m_s2p=mk?tile_find_method(mk,"StructureToPtr",3,"System.Object"):nullptr;
    note("TILE NATIVE corlib=%p Marshal=%p AllocHGlobal(int)=%p StructureToPtr(object,..)=%p",corlib,mk,m_alloc,m_s2p);
    if(!m_alloc||!m_s2p)return;
    long long size=4096;void* a1[1]={&size};void* ex=nullptr;
    void* boxed=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_alloc,nullptr,a1,&ex);
    void* ptr=boxed?*(void**)fn<void*(*)(void*)>(ObjectUnbox)(boxed):nullptr;
    note("TILE NATIVE AllocHGlobal -> %p ex=%p",ptr,ex);
    if(!ptr)return;
    std::memset(ptr,0,4096);
    void* obj=fn<void*(*)(void*,void*)>(ObjectNew)(domain,evk);
    bool set=false;
    {void* fit=nullptr;
     for(int i=0;i<16;++i){
         void* f=fn<void*(*)(void*,void**)>(ClassFields)(evk,&fit);if(!f)break;
         const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
         if(fname&&!std::strcmp(fname,"dataJsonString")){unsigned off=fn<unsigned(*)(void*)>(FieldOffset)(f);
             if(off>=16&&off<256){*(void**)((char*)obj+off)=js;set=true;}break;}}}
    note("TILE NATIVE struct object=%p field set=%d",obj,int(set));
    if(!obj||!set)return;
    long long no_delete=0;void* a3[3]={obj,&ptr,&no_delete};
    ex=nullptr;
    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_s2p,nullptr,a3,&ex);
    note("TILE NATIVE StructureToPtr ex=%p",ex);
    if(ex){tile_log_tostring(ex,"s2p exception");return;}
    {const std::uint64_t* q=(const std::uint64_t*)ptr;
     note("TILE NATIVE buffer qwords: %016llx %016llx %016llx %016llx",(unsigned long long)q[0],(unsigned long long)q[1],(unsigned long long)q[2],(unsigned long long)q[3]);}
    char mn[96];std::snprintf(mn,sizeof mn,"Convert%sEventDataToJObject",kind);
    void* mc=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,mn,1);
    void* argp=ptr;void* ca[1]={&argp};ex=nullptr;
    void* jo=mc?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mc,inst,ca,&ex):nullptr;
    void* exk=ex?fn<void*(*)(void*)>(ObjectClass)(ex):nullptr;
    const char* exn=exk?fn<const char*(*)(void*)>(ClassNameGet)(exk):nullptr;
    note("TILE NATIVE %s(marshalled) -> %p ex=%s",mn,jo,exn?exn:"none");
    if(jo)tile_log_tostring(jo,"native converted");
    if(!emit){note("TILE NATIVE emit skipped (no tile-emit-native marker)");return;}
    if(!jo){note("TILE NATIVE emit refused: conversion gave no object");return;}
    std::snprintf(mn,sizeof mn,"_OnVoiceChat%sEvent",kind);
    void* me=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,mn,1);
    argp=ptr;ex=nullptr;
    if(me)fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(me,inst,ca,&ex);
    note("TILE NATIVE %s invoked (method %p) ex=%p",mn,me,ex);
    if(ex)tile_log_tostring(ex,"native emit exception");
}
// Native event buffer for the RN VoiceChatModule: its event structs hold one field, `string dataJsonString` (metadata of
// IpcTypes.SceVoiceChat*Event), so the IntPtr is taken to point at {char* json}. Convert*EventDataToJObject is a pure
// conversion (logged); _OnVoiceChat*Event emits to the Control Center's JavaScript and only runs when `emit` is set
// (marker file tile-emit) and the conversion produced an object.
[[maybe_unused]] void tile_rn_event_native(void* inst,void* rnk,const char* json,const char* evt_name,bool emit){
    const char* p=std::strstr(evt_name,"voiceChat");
    if(!p||!rnk||!inst)return;
    char kind[32]{};{const char* a=p+9;const char* e=std::strstr(a,"Event");std::size_t n=e?std::size_t(e-a):std::strlen(a);if(n>=sizeof kind)n=sizeof kind-1;std::memcpy(kind,a,n);}
    // Layout A ({char* json} at offset 0) converted to null in run 9: the string field was read as null. The buffer is
    // zero-filled (a wrong guess reads NULL or our own valid text, never stray memory), and each candidate layout is ONE
    // pure Convert call (no emission, nothing sent to JavaScript). The first layout that yields an object is the one
    // used for the emission (marker file only).
    alignas(16) static char buf[8192];
    std::size_t n=std::strlen(json);if(n>1500)n=1500;
    char mn[96];std::snprintf(mn,sizeof mn,"Convert%sEventDataToJObject",kind);
    void* m=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,mn,1);
    void* ex=nullptr;void* jo=nullptr;void* argp=buf;void* args[1]={&argp};
    for(int layout=1;layout<=7&&!jo&&m;++layout){
        std::memset(buf,0,sizeof buf);
        char* u8=buf+256;char* u16=buf+2048;
        std::memcpy(u8,json,n);
        for(std::size_t i=0;i<n;++i){u16[2*i]=json[i];u16[2*i+1]=0;}
        switch(layout){
        case 1:*(void**)(buf+8)=u8;break;                                  // pointer at offset 8
        case 2:*(void**)(buf+16)=u8;break;                                 // pointer at offset 16
        case 3:*(void**)buf=u16;break;                                     // UTF-16 text at offset 0
        case 4:*(void**)(buf+8)=u16;break;                                 // UTF-16 text at offset 8
        case 5:*(void**)buf=buf+128;*(void**)(buf+128)=u8;break;           // pointer to a struct holding the pointer
        case 6:std::memset(buf,0,256);std::memcpy(buf,json,n<255?n:255);break; // the buffer itself is the text (short)
        default:break;}
        if(layout==7){std::memset(buf,0,sizeof buf);for(std::size_t i=0;i<n&&i<1000;++i){buf[2*i]=json[i];}}  // the buffer is UTF-16 text
        ex=nullptr;argp=buf;
        jo=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m,inst,args,&ex);
        void* exk=ex?fn<void*(*)(void*)>(ObjectClass)(ex):nullptr;
        const char* exn=exk?fn<const char*(*)(void*)>(ClassNameGet)(exk):nullptr;
        note("TILE RN layout %d: %s -> %p ex=%s",layout,mn,jo,exn?exn:"none");
        if(jo){note("TILE RN layout %d WORKS",layout);tile_log_tostring(jo,"converted");}}
    if(!jo)note("TILE RN no layout produced an object");
    if(!emit){note("TILE RN emit skipped (no tile-emit marker)");return;}
    if(!jo){note("TILE RN emit refused: conversion gave no object");return;}
    std::snprintf(mn,sizeof mn,"_OnVoiceChat%sEvent",kind);
    void* m2=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,mn,1);
    ex=nullptr;
    if(m2)fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m2,inst,args,&ex);
    note("TILE RN %s invoked (method %p) ex=%p",mn,m2,ex);
    if(ex)tile_log_tostring(ex,"emit exception");
}
// Mode::TileDiscord (lab): forges a Newtonsoft JObject from a JSON string (read from tile.json on disk, or a
// safe default) and dispatches it through VoiceChatModule's own voiceChatModuleEventHandlerDic, as if the
// native voice-chat daemon had raised the event itself. The event name is read from tile-event.txt (default
// "voiceChatDaemonEvent"; the other valid one is "voiceChatChannelEvent"). The native Control Center tile
// then renders with our strings. No hook, no IPMI call, no audio, no PSN: only managed reflection and one
// Invoke on a handler the RN tile itself registered. Idles on probe.lock so it coexists with the audio relay.
State run_tile_discord(){
    publish(State::Observing);
    note("TILE start pid=%d build=0x%016llx",int(getpid()),(unsigned long long)OVERLAY_BUILD);
    static const char default_json[]=
        "{\"header\":{\"type\":\"streamStarted\",\"userId\":1},"
         "\"data\":{\"sessions\":[{\"streamer\":{\"accountId\":\"Discord\",\"deviceId\":0,\"platformType\":0,\"userId\":1},"
         "\"meStreamState\":\"streaming\",\"titleId\":\"Discord\"}]}}";
    char json_buf[4096]; int json_len=0;
    {
        char pth[256];
        if(path(pth,sizeof pth,worker_dir,"tile.json")){
            FILE* f=std::fopen(pth,"rb");
            if(f){
                long n=long(std::fread(json_buf,1,sizeof(json_buf)-1,f));
                if(n<0)n=0; json_buf[n]='\0'; json_len=int(n);
                std::fclose(f); note("TILE read tile.json (%d bytes)",json_len);
            }
        }
    }
    const char* json_cstr=json_len>0?json_buf:default_json;
    char evt_name[64]="voiceChatDaemonEvent";
    {
        char pth[256];
        if(path(pth,sizeof pth,worker_dir,"tile-event.txt")){
            FILE* f=std::fopen(pth,"rb");
            if(f){
                long n=long(std::fread(evt_name,1,sizeof(evt_name)-1,f));
                if(n<0)n=0; evt_name[n]='\0';
                while(n>0&&(evt_name[n-1]=='\n'||evt_name[n-1]=='\r'||evt_name[n-1]==' '||evt_name[n-1]=='\t'))evt_name[--n]='\0';
                std::fclose(f);
            }
        }
    }
    note("TILE event=%s json_len=%d",evt_name,int(std::strlen(json_cstr)));
    domain=fn<void*(*)()>(RootDomain)();
    if(!domain){note("TILE refused: Mono root domain missing");publish(State::Failed);return State::Failed;}
    void* thread=fn<void*(*)(void*)>(ThreadAttach)(domain);
    if(!thread){note("TILE refused: Mono thread attach");publish(State::Failed);return State::Failed;}
    // Metadata only: the Control Center's own voice-chat module lives in the React Native shell assembly, with its own
    // native event registrations. Log its classes so the next run can raise the tile through the right module.
    {
        void* rn=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.ReactNativeShellApp.dll");
        note("TILE RN image=%p",rn);
        struct Ent{const char* ns;const char* name;};
        static const Ent ents[]={
            {"ReactNative.Modules.ShellUI.VoiceChat","VoiceChatModule"},
            {"ReactNative.Modules.ShellUI.VoiceChat","VoiceChatManagerModule"},
            {"ReactNative.Modules.ShellUI.Discord","DiscordAccessorModule"}};
        for(const auto& e:ents){
            void* k=rn?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(rn,e.ns,e.name):nullptr;
            note("TILE RN class %s.%s=%p",e.ns,e.name,k);
            if(k){probe_fields(k,e.name);probe_methods(k,e.name);describe_properties(k,e.name);}}
        // Native event struct types of the RN module: tells whether the IntPtr handed to _OnVoiceChat*Event is text or a struct.
        static const char* const evts[]={"SceVoiceChatChannelEvent","SceVoiceChatMemberEvent","SceVoiceChatVoiceEvent",
            "SceVoiceChatDaemonEvent","SceVoiceChatChannelId","SceVoiceChatMemberAddressData"};
        static const char* const evns[]={"ReactNative.Modules.ShellUI.VoiceChat.IpcTypes","ReactNative.Modules.ShellUI.VoiceChat"};
        for(const char* en:evts){
            void* k=nullptr;const char* used="";
            for(const char* ns:evns){k=rn?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(rn,ns,en):nullptr;if(k){used=ns;break;}}
            note("TILE RN evtclass %s=%p ns=%s",en,k,used);
            if(k)probe_fields(k,en);}
        // NOTE: finding the live RN VoiceChatModule instance by sweeping GC handle ids (567969f) CRASHED ShellUI on 2026-11-23.
        // Never scan handle ids or memory blindly on this Mono; derive the instance from a known root object instead.
        // Known root: VoiceChatModule.m_cblist is a STATIC GCCallBackList (offset 0 = static; instance fields start at 16).
        // It keeps what the module registered with the native voice-chat library. Read the static through the class vtable
        // (class already initialised: the module exists), then dump the list's structure, read-only, to see how it reaches
        // the module instance (delegate targets / contexts). Instance fields would be at >= 16 and are refused here.
        void* rnk=rn?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(rn,"ReactNative.Modules.ShellUI.VoiceChat","VoiceChatModule"):nullptr;
        if(rnk){
            void* it=nullptr;
            for(int i=0;i<256;++i){
                void* f=fn<void*(*)(void*,void**)>(ClassFields)(rnk,&it);if(!f)break;
                const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
                if(!fname||std::strcmp(fname,"m_cblist"))continue;
                unsigned off=fn<unsigned(*)(void*)>(FieldOffset)(f);
                note("TILE RN m_cblist field=%p offset=%u",f,off);
                if(off>=16){note("TILE RN m_cblist looks like an instance field: not read");break;}
                if(!request.functions[MonoClassVtable]||!request.functions[MonoFieldStaticGet]){note("TILE RN static read unavailable (Mono exports missing)");break;}
                void* vt=fn<void*(*)(void*,void*)>(MonoClassVtable)(domain,rnk);
                note("TILE RN class vtable=%p",vt);
                if(!vt)break;
                void* val=nullptr;
                fn<void(*)(void*,void*,void*)>(MonoFieldStaticGet)(vt,f,&val);
                note("TILE RN m_cblist value=%p",val);
                if(val){
                    // GCHandleDict is the instance field at +16 (Dictionary<object,object>).
                    // The list keeps EVERY module instance the Control Center ever created (8 seen, one per reload); the live
                    // one is not known yet. Log each instance's state; emission (marker tile-emit holding an index) targets
                    // exactly one of them and never runs more than once per worker run.
                    void* insts[16];int ninst=0;
                    void* inst_rn=tile_enum_callbacks(*(void**)((char*)val+16),rnk,insts,&ninst,16);
                    note("TILE RN module instances=%d first=%p",ninst,inst_rn);
                    for(int ii=0;ii<ninst;++ii){
                        int nz=0;for(int gi=0;gi<11;++gi)if(*(std::uint64_t*)((char*)insts[ii]+56+8*gi))++nz;
                        note("TILE RN inst[%d]=%p _emittable=%d contexts_set=%d channelCtx=%llx",ii,insts[ii],
                             int(*((unsigned char*)insts[ii]+48)),nz,(unsigned long long)*(std::uint64_t*)((char*)insts[ii]+72));}
                    // Which instance belongs to the Control Center? Each RN app has its own module + ReactContext: dump the
                    // contexts' strings (read-only reference walk) so the app/bundle identity shows up.
                    // (the context graph holds no identity strings: dumped at depth 4 in run 15, nothing found)
                    int emit_index=-1;bool emit_all=false;
                    {char pth[256];if(path(pth,sizeof pth,worker_dir,"tile-emit")){FILE* mf=std::fopen(pth,"rb");
                        if(mf){char d[8]{};std::size_t got=std::fread(d,1,7,mf);std::fclose(mf);emit_index=(got&&d[0]>='0'&&d[0]<='9')?d[0]-'0':ninst-1;
                            if(got&&d[0]=='a')emit_all=true;     // marker "a": every instance gets the event once (which one is the Control Center is unknown)
                            std::remove(pth);}}}   // one-shot: the marker is consumed here
                    if(emit_index>=ninst)emit_index=ninst-1;
                    if(emit_all&&inst_rn){for(int ii=0;ii<ninst;++ii){note("TILE RN emitting to instance %d",ii);tile_rn_event(insts[ii],rnk,json_cstr,evt_name,true);}}
                    else if(inst_rn)tile_rn_event(emit_index>=0?insts[emit_index]:inst_rn,rnk,json_cstr,evt_name,emit_index>=0);
                    // Ground-truth native path (verification always; the real call only with the one-shot marker tile-emit-native).
                    int nat_index=-1;
                    {char pth[256];if(path(pth,sizeof pth,worker_dir,"tile-emit-native")){FILE* mf=std::fopen(pth,"rb");
                        if(mf){char d[8]{};std::size_t got=std::fread(d,1,7,mf);std::fclose(mf);nat_index=(got&&d[0]>='0'&&d[0]<='9')?d[0]-'0':ninst-1;
                            std::remove(pth);}}}
                    if(nat_index>=ninst)nat_index=ninst-1;
                    // DISABLED: Marshal.StructureToPtr on the managed struct crashed ShellUI (run 12, 2026-11-24 00:19).
                    (void)nat_index;}
                break;}
        }
    }
    void* img=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.VoiceChat.dll");
    void* vcm=img?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img,"Sce.Vsh.ShellUI.VoiceChat","VoiceChatModule"):nullptr;
    void* mget=vcm?fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm,"GetInstance",0):nullptr;
    void* ex=nullptr;
    void* inst=mget?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mget,nullptr,nullptr,&ex):nullptr;
    note("TILE VoiceChatModule inst=%p ex=%p",inst,ex);
    if(!inst){fn<void(*)(void*)>(ThreadDetach)(thread);publish(State::Failed);return State::Failed;}
    void* mconv=vcm?fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm,"ConvertJsonStringToJObject",1):nullptr;
    void* mstr=fn<void*(*)(void*,const char*)>(StringNew)(domain,json_cstr);
    void* cargs[1]={mstr};
    ex=nullptr;
    void* jobj=mconv?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mconv,inst,cargs,&ex):nullptr;
    note("TILE ConvertJsonStringToJObject -> %p ex=%p",jobj,ex);
    if(!jobj){fn<void(*)(void*)>(ThreadDetach)(thread);publish(State::Failed);return State::Failed;}
    tile_observe(inst,"before");
    void* dict=*(void**)((char*)inst+16);
    void* dclass=dict?fn<void*(*)(void*)>(ObjectClass)(dict):nullptr;
    void* mitem=dclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(dclass,"get_Item",1):nullptr;
    void* key=fn<void*(*)(void*,const char*)>(StringNew)(domain,evt_name);
    void* iargs[1]={key};
    ex=nullptr;
    void* handler=mitem?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mitem,dict,iargs,&ex):nullptr;
    note("TILE handler for %s = %p ex=%p",evt_name,handler,ex);
    if(!handler){fn<void(*)(void*)>(ThreadDetach)(thread);publish(State::Failed);return State::Failed;}
    void* hclass=fn<void*(*)(void*)>(ObjectClass)(handler);
    void* minvoke=hclass?fn<void*(*)(void*,const char*,int)>(MethodFromName)(hclass,"Invoke",2):nullptr;
    void* key2=fn<void*(*)(void*,const char*)>(StringNew)(domain,evt_name);
    void* vargs[2]={key2,jobj};
    ex=nullptr;
    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(minvoke,handler,vargs,&ex);
    note("TILE handler.Invoke done ex=%p",ex);
    usleep(1000000);
    tile_observe(inst,"after");
    if(ex){
        // Diagnostic: print Exception.ToString() (type, message, first stack lines), split in 200-char lines.
        void* eclass=fn<void*(*)(void*)>(ObjectClass)(ex);
        {
            const char* en=eclass?fn<const char*(*)(void*)>(ClassNameGet)(eclass):nullptr;
            note("TILE exc class=%s",en?en:"?");
        }
        void* mts=nullptr;
        for(void* walk=eclass;walk&&!mts;walk=fn<void*(*)(void*)>(ClassParent)(walk))
            mts=fn<void*(*)(void*,const char*,int)>(MethodFromName)(walk,"ToString",0);
        void* ex2=nullptr;
        void* s=mts?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mts,ex,nullptr,&ex2):nullptr;
        note("TILE exception ToString=%p class=%p ex2=%p",s,eclass,ex2);
        if(s){
            int slen=*(int*)((char*)s+16);
            const unsigned short* su=(const unsigned short*)((char*)s+20);
            if(slen>1800)slen=1800;
            char line[208];int w=0;
            for(int j=0;j<slen;++j){
                unsigned short c=su[j];
                if(c=='\n'||c=='\r'||w>=200){if(w){line[w]='\0';note("TILE exc: %s",line);w=0;}if(c=='\n'||c=='\r')continue;}
                line[w++]=(c>=0x20&&c<0x7f)?char(c):'?';}
            if(w){line[w]='\0';note("TILE exc: %s",line);}
        }
    }
    // Idle so the user can see the tile and the stop file can cut us short.
    const std::uint64_t deadline=request.deadline_ms>6000?request.deadline_ms-6000:now_ms()+20000;
    while(now_ms()<deadline){
        std::uint64_t stop=0;
        if(read_file(worker_dir,"stop.bin",stop)&&stop==request.token)break;
        publish(State::Observing);
        usleep(500000);}
    fn<void(*)(void*)>(ThreadDetach)(thread);
    note("TILE done");
    publish(State::Passed);return State::Passed;
}
// Mode::NativeTileInject (lab): continuously read voice state from the homebrew core (tile-state.json,
// written by src/overlay.c) and emit events to the Control Center's JavaScript tile through the Mono→Hermes
// bridge (EventEmitterUtility.emitDeviceEvent). The tile's React components (ActionCardRealTimeCommunication,
// PartySessionListProvider) re-render with the injected data. No hook, no IPMI, no PSN: only managed
// reflection and emitDeviceEvent calls. Coexists with AudioRelay via probe.lock.
// The event name defaults to "voiceChatChannelEvent" but can be overridden by tile-event.txt.
State run_native_tile_inject(){
    publish(State::Observing);
    note("TILEINJECT start pid=%d build=0x%016llx",int(getpid()),(unsigned long long)OVERLAY_BUILD);
    domain=fn<void*(*)()>(RootDomain)();
    if(!domain){note("TILEINJECT refused: Mono root domain missing");publish(State::Failed);return State::Failed;}
    void* thread=fn<void*(*)(void*)>(ThreadAttach)(domain);
    if(!thread){note("TILEINJECT refused: Mono thread attach");publish(State::Failed);return State::Failed;}
    // Find the ReactNative VoiceChatModule class and its live instance through the static m_cblist field,
    // exactly as Mode::TileDiscord does. This gives us ConvertJsonStringToJObject and the ReactContext.
    void* rn=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.ReactNativeShellApp.dll");
    note("TILEINJECT RN image=%p",rn);
    void* rnk=rn?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(rn,"ReactNative.Modules.ShellUI.VoiceChat","VoiceChatModule"):nullptr;
    note("TILEINJECT RN VoiceChatModule class=%p",rnk);
    if(!rnk){fn<void(*)(void*)>(ThreadDetach)(thread);publish(State::Failed);return State::Failed;}
    // Find ALL instances through static m_cblist → GCCallBackList → enumerate delegates.
    // ShellUI has multiple React instances (home, control center, settings, etc.); the tile
    // handler may live in any of them, so we collect all and emit to every context.
    void* inst_rn=nullptr;
    void* all_insts[16];int ninst=0;
    {void* it=nullptr;
     for(int i=0;i<256;++i){
         void* f=fn<void*(*)(void*,void**)>(ClassFields)(rnk,&it);if(!f)break;
         const char* fname=fn<const char*(*)(void*)>(FieldName)(f);
         if(!fname||std::strcmp(fname,"m_cblist"))continue;
         unsigned off=fn<unsigned(*)(void*)>(FieldOffset)(f);
         if(off>=16){note("TILEINJECT m_cblist looks like instance field");break;}
         if(!request.functions[MonoClassVtable]||!request.functions[MonoFieldStaticGet]){note("TILEINJECT Mono vtable/static exports missing");break;}
         void* vt=fn<void*(*)(void*,void*)>(MonoClassVtable)(domain,rnk);
         if(!vt){note("TILEINJECT class vtable=null");break;}
         void* val=nullptr;
         fn<void(*)(void*,void*,void*)>(MonoFieldStaticGet)(vt,f,&val);
         note("TILEINJECT m_cblist=%p",val);
         if(!val)break;
         inst_rn=tile_enum_callbacks(*(void**)((char*)val+16),rnk,all_insts,&ninst,16);
         note("TILEINJECT RN instances=%d first=%p",ninst,inst_rn);
         break;}}
    if(!inst_rn){note("TILEINJECT no VoiceChatModule instance found");fn<void(*)(void*)>(ThreadDetach)(thread);publish(State::Failed);return State::Failed;}
    // Collect contexts for ALL instances and log them
    void* all_ctx[16]={};
    for(int ci=0;ci<ninst;++ci){
        all_ctx[ci]=tile_get_context(all_insts[ci]);
        note("TILEINJECT inst[%d]=%p ctx=%p",ci,all_insts[ci],all_ctx[ci]);
    }
    // Build A (read-only): dump the JS-bridge surface of the first live Control Center ReactContext,
    // to learn how to run our own JS (addActionCard) in it. Pure reflection logging, invokes nothing.
    note("TILEINJECT JSBRIDGE probe start contexts=%d",ninst);
    for(int ci=0;ci<ninst;++ci)if(all_ctx[ci]){note("TILE JSBRIDGE === ctx[%d]=%p ===",ci,all_ctx[ci]);tile_dump_js_bridge(all_ctx[ci]);break;}
    // Resolve the emission tools: ConvertJsonStringToJObject, ReactContext, EventEmitterUtility.emitDeviceEvent
    void* m_convert=fn<void*(*)(void*,const char*,int)>(MethodFromName)(rnk,"ConvertJsonStringToJObject",1);
    void* cimg=image("/system_ex/common_ex/lib/ReactNative.Vsh.Common.dll");
    void* eu=cimg?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(cimg,"ReactNative.Vsh.Common","EventEmitterUtility"):nullptr;
    void* m_emit=eu?tile_find_method(eu,"emitDeviceEvent",3,"ReactNative.Bridge.ReactContext"):nullptr;
    note("TILEINJECT convert=%p emitter=%p emit=%p",m_convert,eu,m_emit);
    if(!m_convert||!m_emit){
        note("TILEINJECT emission pipeline incomplete, falling back to handler path");
    }
    // Also resolve the VoiceChatModule handler dictionary path (fallback / voiceChat events)
    void* img_vcm=image("/system_ex/common_ex/lib/Sce.Vsh.ShellUI.VoiceChat.dll");
    void* vcm_class=img_vcm?fn<void*(*)(void*,const char*,const char*)>(ClassFromName)(img_vcm,"Sce.Vsh.ShellUI.VoiceChat","VoiceChatModule"):nullptr;
    void* m_getinst=vcm_class?fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm_class,"GetInstance",0):nullptr;
    void* ex=nullptr;
    void* vcm_inst=m_getinst?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_getinst,nullptr,nullptr,&ex):nullptr;
    note("TILEINJECT VoiceChatModule(Mono) inst=%p",vcm_inst);
    // Diagnostic: enumerate ALL keys in the voiceChatModuleEventHandlerDic (vcm_inst offset 16)
    if(vcm_inst){
        void* ehd=*(void**)((char*)vcm_inst+16);
        if(ehd){
            void* edc=fn<void*(*)(void*)>(ObjectClass)(ehd);
            const char* dcn=edc?fn<const char*(*)(void*)>(ClassNameGet)(edc):"?";
            note("TILEINJECT dict class=%s",dcn);
            void* mgk=edc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(edc,"get_Keys",0):nullptr;
            void* ex2=nullptr;
            void* keys=mgk?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mgk,ehd,nullptr,&ex2):nullptr;
            if(keys){
                void* kc=fn<void*(*)(void*)>(ObjectClass)(keys);
                void* me=kc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(kc,"GetEnumerator",0):nullptr;
                ex2=nullptr;
                void* en=me?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(me,keys,nullptr,&ex2):nullptr;
                if(en){
                    void* ec=fn<void*(*)(void*)>(ObjectClass)(en);
                    void* mmn=nullptr;void* mcur=nullptr;
                    for(void* w=ec;w;w=fn<void*(*)(void*)>(ClassParent)(w)){
                        if(!mmn)mmn=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"MoveNext",0);
                        if(!mcur)mcur=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"get_Current",0);}
                    int nk=0;
                    while(mmn){
                        ex2=nullptr;
                        void* mr=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mmn,en,nullptr,&ex2);
                        if(!mr||!*(unsigned char*)((char*)mr+16))break;
                        ex2=nullptr;
                        void* cur=mcur?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mcur,en,nullptr,&ex2):nullptr;
                        if(cur){
                            int slen=*(int*)((char*)cur+16);const unsigned short* su=(const unsigned short*)((char*)cur+20);
                            char buf[128];int w2=0;for(int j=0;j<slen&&j<int(sizeof buf)-1;++j)buf[w2++]=(su[j]<0x80)?char(su[j]):'?';buf[w2]='\0';
                            // Also get the handler for this key
                            void* mgi=edc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(edc,"get_Item",1):nullptr;
                            void* ka[1]={cur};ex2=nullptr;
                            void* hv=mgi?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mgi,ehd,ka,&ex2):nullptr;
                            const char* hcn="?";
                            if(hv){void* hvc=fn<void*(*)(void*)>(ObjectClass)(hv);hcn=hvc?fn<const char*(*)(void*)>(ClassNameGet)(hvc):"?";}
                            note("TILEINJECT dict[%d]=\"%s\" handler=%s",nk,buf,hcn);
                        }
                        ++nk;if(nk>20)break;
                    }
                    note("TILEINJECT dict has %d keys",nk);
                }
            } else note("TILEINJECT dict keys=null");
        } else note("TILEINJECT dict=null");
    }
    // Locate PartyStatusMonitor and pre-seed it: set m_isInParty=1 and add "discord-1" to
    // m_joinedTargetChannels.  Offsets verified by tile_observe (32=m_isInParty, 24=m_joinedTargetChannels).
    void* psm=nullptr;
    if(vcm_inst){
        void* d0=*(void**)((char*)vcm_inst+16);
        void* d0c=d0?fn<void*(*)(void*)>(ObjectClass)(d0):nullptr;
        void* d0gi=d0c?fn<void*(*)(void*,const char*,int)>(MethodFromName)(d0c,"get_Item",1):nullptr;
        void* k0=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatChannelEvent");
        void* a0[1]={k0};ex=nullptr;
        void* h0=d0gi?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(d0gi,d0,a0,&ex):nullptr;
        if(h0){
            void* gt=nullptr;
            for(void* w=fn<void*(*)(void*)>(ObjectClass)(h0);w&&!gt;w=fn<void*(*)(void*)>(ClassParent)(w))
                gt=fn<void*(*)(void*,const char*,int)>(MethodFromName)(w,"get_Target",0);
            ex=nullptr;
            psm=gt?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(gt,h0,nullptr,&ex):nullptr;}
        if(psm){
            void* pc=fn<void*(*)(void*)>(ObjectClass)(psm);
            const char* cn=pc?fn<const char*(*)(void*)>(ClassNameGet)(pc):nullptr;
            if(!cn||std::strcmp(cn,"PartyStatusMonitor")){note("TILEINJECT PSM class=%s (not PartyStatusMonitor)",cn?cn:"?");psm=nullptr;}
            else{
                note("TILEINJECT PSM=%p m_isInParty=%d",psm,int(*((unsigned char*)psm+32)));
                *((unsigned char*)psm+32)=1;
                note("TILEINJECT PSM m_isInParty forced to 1");
                void* ch=*(void**)((char*)psm+24);
                if(ch){void* chc=fn<void*(*)(void*)>(ObjectClass)(ch);
                    void* madd=chc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(chc,"Add",1):nullptr;
                    if(madd){void* ds=fn<void*(*)(void*,const char*)>(StringNew)(domain,"discord-1");
                        void* aa[1]={ds};ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(madd,ch,aa,&ex);
                        note("TILEINJECT PSM m_joinedTargetChannels.Add ex=%p",ex);}}
            }
        } else note("TILEINJECT PSM not found");
    }
    // Read the event name (configurable, default voiceChatChannelEvent)
    char evt_name[64]="voiceChatChannelEvent";
    {char pth[256];
     if(path(pth,sizeof pth,worker_dir,"tile-event.txt")){
         FILE* f=std::fopen(pth,"rb");
         if(f){long n=long(std::fread(evt_name,1,sizeof(evt_name)-1,f));
             if(n<0)n=0;evt_name[n]='\0';
             while(n>0&&(evt_name[n-1]=='\n'||evt_name[n-1]=='\r'||evt_name[n-1]==' '))evt_name[--n]='\0';
             std::fclose(f);}}}
    note("TILEINJECT event_name=%s",evt_name);
    // Main loop: read tile-state.json, convert, emit, sleep
    char last_json[4096]={};
    int emit_count=0;
    const std::uint64_t deadline=request.deadline_ms>6000?request.deadline_ms-6000:now_ms()+86400000ULL;
    while(now_ms()<deadline){
        std::uint64_t stop=0;
        if(read_file(worker_dir,"stop.bin",stop)&&stop==request.token)break;
        publish(State::Observing);
        // Read tile-state.json (written by the core's feed loop in src/overlay.c)
        char json_buf[4096]={};int json_len=0;
        {char pth[256];
         if(path(pth,sizeof pth,worker_dir,"tile-state.json")){
             FILE* f=std::fopen(pth,"rb");
             if(f){long n=long(std::fread(json_buf,1,sizeof(json_buf)-1,f));
                 if(n<0)n=0;json_buf[n]='\0';json_len=int(n);
                 std::fclose(f);}}}
        if(json_len>2&&std::strcmp(json_buf,last_json)!=0){
            note("TILEINJECT new state (%d bytes), emitting events",json_len);
            std::memcpy(last_json,json_buf,sizeof last_json);
            ++emit_count;
            // Build payloads matching the REAL VoiceChatModule JObject format discovered from
            // Sce.Vsh.ShellUI.VoiceChat.dll.sprx UTF-16 string analysis:
            //   {header:{type:"<string>"},data:{...}}
            // Event names: voiceChatDaemonEvent (daemon state) and voiceChatChannelEvent (session data).
            // Channel types include "DISCORD" — a first-class value in Sony's enum.
            // The JS code that listens for these events handles the AutoMounter trigger and
            // PartySessionList updates internally — we don't need to emit to secondary event names.
            // --- jobj_daemon: daemon init event (triggers AutoMounter + voice system) ---
            static const char daemon_json[]=
                "{\"header\":{\"type\":\"started\"},\"data\":{\"errorCode\":0,\"daemonState\":1,"
                "\"isMicConnected\":true,\"isMicMuted\":false,\"isConnectionLost\":false,"
                "\"connectionStateChanged\":false,\"sharePartyAudio\":false,"
                "\"sharePartyAudioForGls\":false,\"sharePartyAudioForRec\":false}}";
            void* js_d=fn<void*(*)(void*,const char*)>(StringNew)(domain,daemon_json);
            void* da[1]={js_d};ex=nullptr;
            void* jobj_daemon=m_convert?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_convert,inst_rn,da,&ex):nullptr;
            if(ex){note("TILEINJECT convert daemon exception");ex=nullptr;}
            // --- jobj_channel: channel sessionUpdated event (Discord channel data) ---
            char channel_json[8192];
            std::snprintf(channel_json,sizeof channel_json,
                "{\"header\":{\"type\":\"sessionUpdated\"},\"data\":{\"channels\":["
                "{\"channelType\":\"DISCORD\",\"channelId\":\"discord-1\","
                "\"activeChannelId\":\"discord-1\"}]}}");
            void* js_c=fn<void*(*)(void*,const char*)>(StringNew)(domain,channel_json);
            void* ca[1]={js_c};ex=nullptr;
            void* jobj_channel=m_convert?fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_convert,inst_rn,ca,&ex):nullptr;
            if(ex){note("TILEINJECT convert channel exception");ex=nullptr;}
            if(emit_count<=2) note("TILEINJECT payloads daemon=%p channel=%p",jobj_daemon,jobj_channel);
            // ---- MULTI-CONTEXT EMISSION: emit to ALL React contexts, not just the first. ----
            // ShellUI has multiple React instances (home screen, control center, etc.); only one
            // has the active VoiceChat listener. Emitting to all avoids guessing the right one.
            // On the first emission round, also send a test event per context (type "probe_N") to
            // identify which context has the daemon handler (it logs "unknown daemon event" for
            // unrecognised types).
            for(int ci=0;ci<ninst;++ci){
                void* cctx=all_ctx[ci];
                if(!cctx)continue;
                // On the first round only, emit a per-context probe to identify the listening context
                if(emit_count==1&&jobj_daemon&&m_emit&&m_convert){
                    char probe_json[256];
                    std::snprintf(probe_json,sizeof probe_json,
                        "{\"header\":{\"type\":\"probe_%d\"},\"data\":{\"errorCode\":0}}",ci);
                    void* js_p=fn<void*(*)(void*,const char*)>(StringNew)(domain,probe_json);
                    void* pa2[1]={js_p};ex=nullptr;
                    void* jobj_probe=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_convert,all_insts[ci],pa2,&ex);
                    if(jobj_probe){
                        void* pn2=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatDaemonEventVshNMVoiceChat");
                        void* pargs2[3]={cctx,pn2,jobj_probe};
                        ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,pargs2,&ex);
                        note("TILEINJECT PROBE ctx[%d]=%p daemon emit %s",ci,cctx,ex?"exception":"ok");
                    }
                }
                // Path I: voiceChatDaemonEventVshNMVoiceChat to this context
                if(jobj_daemon&&m_emit){
                    void* in1=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatDaemonEventVshNMVoiceChat");
                    void* ia1[3]={cctx,in1,jobj_daemon};
                    ex=nullptr;
                    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,ia1,&ex);
                    if(emit_count<=2) note("TILEINJECT I ctx[%d] daemonVshNM %s",ci,ex?"exception":"ok");
                }
                // Path J: voiceChatChannelEventVshNMVoiceChat to this context
                if(jobj_channel&&m_emit){
                    void* jn1=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatChannelEventVshNMVoiceChat");
                    void* ja1[3]={cctx,jn1,jobj_channel};
                    ex=nullptr;
                    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,ja1,&ex);
                    if(emit_count<=2) note("TILEINJECT J ctx[%d] channelVshNM %s",ci,ex?"exception":"ok");
                }
                // Path C: voiceChatDaemonEventForAutoMounter to this context
                if(jobj_daemon&&m_emit){
                    void* an=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatDaemonEventForAutoMounter");
                    void* aargs[3]={cctx,an,jobj_daemon};
                    ex=nullptr;
                    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,aargs,&ex);
                    if(emit_count<=2) note("TILEINJECT C ctx[%d] autoMounter %s",ci,ex?"exception":"ok");
                }
                // Path E: partySessionListEventVshNMVoiceChat to this context
                if(m_emit&&m_convert){
                    static const char psl_json[]=
                        "{\"header\":{\"type\":\"sessionCreated\"},\"data\":{\"channels\":["
                        "{\"channelType\":\"DISCORD\",\"channelId\":\"discord-1\","
                        "\"activeChannelId\":\"discord-1\"}]}}";
                    void* js_psl=fn<void*(*)(void*,const char*)>(StringNew)(domain,psl_json);
                    void* pa[1]={js_psl};ex=nullptr;
                    void* jobj_psl=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_convert,all_insts[ci],pa,&ex);
                    if(jobj_psl){
                        void* pn=fn<void*(*)(void*,const char*)>(StringNew)(domain,"partySessionListEventVshNMVoiceChat");
                        void* pargs[3]={cctx,pn,jobj_psl};
                        ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,pargs,&ex);
                        if(emit_count<=2) note("TILEINJECT E ctx[%d] partySessionList %s",ci,ex?"exception":"ok");
                    }
                }
            }
            // Bare-name emission (the CORRECT event names for JS — the VshNM-suffixed versions
            // voiceChatDaemonEventVshNMVoiceChat / voiceChatChannelEventVshNMVoiceChat do NOT exist
            // in the HBC string table, so the JS code never listens on them).
            for(int ci=0;ci<ninst;++ci){
                void* cctx=all_ctx[ci];
                if(!cctx)continue;
                if(jobj_daemon&&m_emit){
                    void* dn=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatDaemonEvent");
                    void* dargs[3]={cctx,dn,jobj_daemon};
                    ex=nullptr;
                    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,dargs,&ex);
                    if(emit_count<=2) note("TILEINJECT A ctx[%d] daemon %s",ci,ex?"exception":"ok");
                }
                if(jobj_channel&&m_emit){
                    void* cn=fn<void*(*)(void*,const char*)>(StringNew)(domain,"voiceChatChannelEvent");
                    void* cargs2[3]={cctx,cn,jobj_channel};
                    ex=nullptr;
                    fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m_emit,nullptr,cargs2,&ex);
                    if(emit_count<=2) note("TILEINJECT B ctx[%d] channel %s",ci,ex?"exception":"ok");
                }
            }
            // Path G: invoke the voiceChatModuleEventHandlerDic handlers directly.
            if(vcm_inst){
                void* ehd=*(void**)((char*)vcm_inst+16);
                void* edc=ehd?fn<void*(*)(void*)>(ObjectClass)(ehd):nullptr;
                void* mgi2=edc?fn<void*(*)(void*,const char*,int)>(MethodFromName)(edc,"get_Item",1):nullptr;
                static const char* const dk[]={"voiceChatDaemonEvent","voiceChatChannelEvent"};
                void* const dv[]={jobj_daemon,jobj_channel};
                for(int di=0;di<2;++di){
                    if(!dv[di]||!mgi2)continue;
                    void* dkey=fn<void*(*)(void*,const char*)>(StringNew)(domain,dk[di]);
                    void* dka[1]={dkey};ex=nullptr;
                    void* handler=fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(mgi2,ehd,dka,&ex);
                    if(!handler){if(emit_count<=2) note("TILEINJECT G %s no handler",dk[di]);continue;}
                    void* hclass=fn<void*(*)(void*)>(ObjectClass)(handler);
                    const char* hcn=hclass?fn<const char*(*)(void*)>(ClassNameGet)(hclass):"?";
                    if(emit_count<=2) note("TILEINJECT G %s handler class=%s",dk[di],hcn);
                    // Try Invoke with 0, 1, 2 params and DynamicInvoke
                    void* minv0=nullptr;void* minv1=nullptr;void* minv2=nullptr;void* mdyn=nullptr;
                    for(void* wk=hclass;wk;wk=fn<void*(*)(void*)>(ClassParent)(wk)){
                        if(!minv0)minv0=fn<void*(*)(void*,const char*,int)>(MethodFromName)(wk,"Invoke",0);
                        if(!minv1)minv1=fn<void*(*)(void*,const char*,int)>(MethodFromName)(wk,"Invoke",1);
                        if(!minv2)minv2=fn<void*(*)(void*,const char*,int)>(MethodFromName)(wk,"Invoke",2);
                        if(!mdyn)mdyn=fn<void*(*)(void*,const char*,int)>(MethodFromName)(wk,"DynamicInvoke",1);}
                    if(emit_count<=2) note("TILEINJECT G %s Invoke(0)=%p (1)=%p (2)=%p DynInvoke=%p",dk[di],minv0,minv1,minv2,mdyn);
                    if(minv2){
                        void* iva[2]={nullptr,dv[di]};ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(minv2,handler,iva,&ex);
                        if(emit_count<=2) note("TILEINJECT G %s Invoke(2) %s",dk[di],ex?"exception":"ok");
                    }
                    if(minv1){
                        void* iva[1]={dv[di]};ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(minv1,handler,iva,&ex);
                        if(emit_count<=2) note("TILEINJECT G %s Invoke(1) %s",dk[di],ex?"exception":"ok");
                    }
                    if(minv0&&!minv1&&!minv2){
                        ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(minv0,handler,nullptr,&ex);
                        if(emit_count<=2) note("TILEINJECT G %s Invoke(0) %s",dk[di],ex?"exception":"ok");
                    }
                    if(mdyn&&emit_count<=2) note("TILEINJECT G %s DynamicInvoke available but array alloc not impl",dk[di]);
                }
            }
            // Path H: call OnDaemonEvent / OnChannelEvent on the Sce.Vsh VoiceChatModule directly.
            // This is the managed entry point that the native P/Invoke callback triggers.
            // Try with 0, 1, and 2 params since we don't know the exact signature.
            if(vcm_inst&&vcm_class){
                static const char* const hnames[]={"OnDaemonEvent","OnChannelEvent"};
                void* const hdata[]={jobj_daemon,jobj_channel};
                for(int hi=0;hi<2;++hi){
                    if(!hdata[hi])continue;
                    void* m0=fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm_class,hnames[hi],0);
                    void* m1=fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm_class,hnames[hi],1);
                    void* m2=fn<void*(*)(void*,const char*,int)>(MethodFromName)(vcm_class,hnames[hi],2);
                    if(emit_count<=2) note("TILEINJECT H %s (0)=%p (1)=%p (2)=%p",hnames[hi],m0,m1,m2);
                    if(m1){
                        void* ha[1]={hdata[hi]};ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m1,vcm_inst,ha,&ex);
                        if(emit_count<=2) note("TILEINJECT H %s(1) %s",hnames[hi],ex?"exception":"ok");
                    }
                    if(m2){
                        void* ha[2]={nullptr,hdata[hi]};ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m2,vcm_inst,ha,&ex);
                        if(emit_count<=2) note("TILEINJECT H %s(2) %s",hnames[hi],ex?"exception":"ok");
                    }
                    if(m0&&!m1&&!m2){
                        ex=nullptr;
                        fn<void*(*)(void*,void*,void**,void**)>(RuntimeInvoke)(m0,vcm_inst,nullptr,&ex);
                        if(emit_count<=2) note("TILEINJECT H %s(0) %s",hnames[hi],ex?"exception":"ok");
                    }
                }
            }
            // Path D: keep PartyStatusMonitor.m_isInParty=1
            if(psm){*((unsigned char*)psm+32)=1;
                if(emit_count<=1) tile_observe(vcm_inst,"after-force");}
            if(!jobj_daemon&&!jobj_channel) note("TILEINJECT convert failed or no emission path");
        }
        usleep(2000000); // 2s between reads
    }
    fn<void(*)(void*)>(ThreadDetach)(thread);
    note("TILEINJECT done emits=%d",emit_count);
    publish(emit_count>0?State::Passed:State::Failed);
    return emit_count>0?State::Passed:State::Failed;
}
// Mode::BundleDump (lab): dump the Control Center's Hermes bytecode without waiting for the system to
// load it. The RNPS container is decrypted by a kernel routine (libSceRnpsBundle sub_6f80: it opens
// /dev/rnps and ioctls the buffer, which the kernel decrypts in place) that needs no certificate
// context. So we read application.ps.bundle from disk, call that routine on it, and copy out the
// plaintext bytecode section. One shot on inject; writes only our own file, never system memory.
State run_bundle_dump(){
    publish(State::Observing);
    note("BUNDLEDUMP v2 start pid=%d",int(getpid()));
    const std::uint64_t verify_export=request.functions[RnpsVerifyDecrypt];
    if(!address(verify_export)){note("BUNDLEDUMP refused: RNPS export not resolved");publish(State::Failed);return State::Failed;}
    const std::uint64_t base=verify_export-kRnpsVerifyExportOffset;
    auto rnps_decrypt=reinterpret_cast<int(*)(void*,unsigned)>(base+kRnpsDecryptOffset);
    // Safety gate: confirm the computed address is inside an executable mapping before calling it,
    // using the system's protection query -- WITHOUT reading the bytes. System code pages here are
    // execute-only (reading them faults, which is what crashed ShellUI before); executing is allowed.
    // If the address is not in an executable region (wrong base/offset, or the lib differs), we refuse.
    {
        auto query=fn<ProtectionQuery>(QueryProtection);
        void* lo=nullptr;void* hi=nullptr;int prot=0;
        if(!query||query(reinterpret_cast<void*>(base+kRnpsDecryptOffset),&lo,&hi,&prot)||!(prot&PROT_EXEC)){
            note("BUNDLEDUMP refused: decrypt address %p not in an executable region (prot=%d)",reinterpret_cast<void*>(base+kRnpsDecryptOffset),prot);
            publish(State::Failed);return State::Failed;}
    }
    // Read the raw RNPSHEDR container. In ShellUI's sandbox the apps live under /mnt/rnps.
    const char* paths[]={"/mnt/rnps/apps/NPXS40003/application.ps.bundle",
                         "/system_ex/rnps/apps/NPXS40003/application.ps.bundle"};
    FILE* f=nullptr;const char* used=nullptr;
    for(const char* cand:paths){if((f=std::fopen(cand,"rb"))){used=cand;break;}}
    if(!f){note("BUNDLEDUMP refused: cannot open the bundle file (errno=%d)",errno);publish(State::Failed);return State::Failed;}
    std::fseek(f,0,SEEK_END);const long fsz=std::ftell(f);std::fseek(f,0,SEEK_SET);
    if(fsz<=0x1000||fsz>0x800000){std::fclose(f);note("BUNDLEDUMP refused: unexpected bundle size %ld",fsz);publish(State::Failed);return State::Failed;}
    auto do_mmap=fn<MmapCall>(TargetMmap);
    if(!do_mmap){std::fclose(f);note("BUNDLEDUMP refused: mmap unavailable");publish(State::Failed);return State::Failed;}
    const std::size_t cap=(std::size_t(fsz)+0xffff)&~std::size_t(0xffff);
    auto* buf=static_cast<unsigned char*>(do_mmap(nullptr,cap,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0));
    if(!buf||buf==reinterpret_cast<void*>(-1)){std::fclose(f);note("BUNDLEDUMP refused: buffer mmap failed");publish(State::Failed);return State::Failed;}
    const std::size_t got=std::fread(buf,1,std::size_t(fsz),f);std::fclose(f);
    if(got!=std::size_t(fsz)||std::memcmp(buf,"RNPSHEDR",8)!=0){
        note("BUNDLEDUMP refused: read %zu/%ld or not RNPSHEDR on disk",got,fsz);publish(State::Failed);return State::Failed;}
    note("BUNDLEDUMP read %s (%ld bytes); calling decrypt @%p (base=%p)",used,fsz,
        reinterpret_cast<void*>(base+kRnpsDecryptOffset),reinterpret_cast<void*>(base));
    const int rc=rnps_decrypt(buf,static_cast<unsigned>(fsz));
    std::uint32_t off=0,len=0;std::memcpy(&off,buf+0x1c,4);std::memcpy(&len,buf+0x20,4);
    static const unsigned char hbc_magic[8]={0xC6,0x1F,0xBC,0x03,0xC1,0x03,0x19,0x1F};
    const bool in_range=std::uint64_t(off)+len<=std::uint64_t(std::size_t(fsz));
    const bool magic_ok=in_range&&len>=8&&std::memcmp(buf+off,hbc_magic,8)==0;
    note("BUNDLEDUMP decrypt rc=%d off=0x%x len=0x%x hbc_magic=%d",rc,unsigned(off),unsigned(len),magic_ok?1:0);
    bool wrote=false;
    if(magic_ok){
        char p[256];
        if(path(p,sizeof p,worker_dir,"npxs40003.hbc")){
            FILE* o=std::fopen(p,"wb");
            if(o){const std::size_t w=std::fwrite(buf+off,1,len,o);bool ok=(w==len);if(std::fclose(o))ok=false;wrote=ok;
                note("BUNDLEDUMP wrote %s len=%u ok=%d",p,unsigned(len),ok?1:0);}
            else note("BUNDLEDUMP fopen out failed errno=%d",errno);}
    } else {
        note("BUNDLEDUMP no plaintext: rc=%d off=0x%x len=0x%x in_range=%d",rc,unsigned(off),unsigned(len),in_range?1:0);
        if(in_range&&len>=8)
            note("BUNDLEDUMP head=%02x%02x%02x%02x%02x%02x%02x%02x",
                buf[off],buf[off+1],buf[off+2],buf[off+3],buf[off+4],buf[off+5],buf[off+6],buf[off+7]);
    }
    const State result=wrote?State::Passed:State::Failed;
    publish(result);return result;
}
State run(){
    if(request.mode==Mode::AudioTest)return run_audio_test();
    if(request.mode==Mode::AudioRelay)return run_audio_relay();
    if(request.mode==Mode::PartyProbe)return run_party_probe();
    if(request.mode==Mode::SceneProbe)return run_scene_probe();
    if(request.mode==Mode::TileDiscord)return run_tile_discord();
    if(request.mode==Mode::BundleDump)return run_bundle_dump();
    if(request.mode==Mode::NativeTileInject)return run_native_tile_inject();
    domain=fn<void*(*)()>(RootDomain)();if(!domain){note("REFUSED root domain missing");return State::Refused;}
    void* thread=fn<void*(*)(void*)>(ThreadAttach)(domain);if(!thread){note("REFUSED Mono thread attach");return State::Refused;}
    State result=State::Refused;
    do {
        if(request.mode==Mode::Input){
            if(!resolve_input_methods())break;
            note("OBSERVING pad and share for at most60seconds; pure pass-through, no button changes");
        } else {
            void* entry=nullptr;
            if(!resolve_update_methods()||!(entry=resolved_update_entry))break;
            if(request.mode==Mode::Resolve){result=State::Resolved;break;}
            if(!prepare_update_hook(entry))break;
            enabled.store(true,std::memory_order_release);
            if(draws(request.mode)&&install_pad_hook())
                input_enabled.store(true,std::memory_order_release);
            note("OBSERVING Update%s for %s; %s",
                draws(request.mode)?" plus the app's widgets":"",
                request.mode==Mode::Service?"as long as the loader's keepalive is fresh":
                request.mode==Mode::Widget?"at most 60 seconds":"at most 8 seconds",
                draws(request.mode)?"widgets removed on stop or deadline":"no widgets, pad hooks or focus calls");
        }
        auto deadline=now_ms()+(request.mode==Mode::Widget||request.mode==Mode::Input?60000:8000);
        if(deadline>request.deadline_ms)deadline=request.deadline_ms;
        const std::uint64_t began=now_ms();
        for(;;){
            std::uint64_t stop=0;if(read_file(worker_dir,"stop.bin",stop)&&stop==request.token)break;
            if(request.mode==Mode::Service){
                // No fixed end: the loader's heartbeat keeps it. A stale or foreign one
                // (the loader is gone) ends it, after a grace for the first beat.
                Keepalive k;const std::uint64_t now=now_ms();
                const bool fresh=read_file(worker_dir,"keepalive.bin",k)&&k.signature==magic&&
                    k.token==request.token&&k.at_ms<=now+1000&&(k.at_ms>now||now-k.at_ms<keepalive_stale_ms);
                if(!fresh&&now-began>2*keepalive_stale_ms){note("SERVICE keepalive stale; tearing down");break;}
            } else if(now_ms()>=deadline)break;
            publish(State::Observing);usleep(200000);
        }
        if(draws(request.mode)){
            teardown.store(true,std::memory_order_release);
            for(unsigned wait=0;wait<100&&widget_removed.load(std::memory_order_acquire)==0;wait++){
                publish(State::Observing);usleep(20000);}
            // CAS so a removal completing on the UI thread in this window is
            // never overwritten by the timeout verdict.
            int stalled=0;
            if(widget_removed.compare_exchange_strong(stalled,-1))
                note("WIDGET teardown timed out; UI thread stalled, cleanup left to ShellUI restart");
            note("WIDGET teardown result=%d",widget_removed.load());
            result=updates.load()>0&&widgets_created.load()==1&&widget_removed.load()==1
                ?State::Passed:State::Failed;
        } else if(request.mode==Mode::Input){
            result=pad_polls.load()>0?State::Passed:State::Failed;
        } else {
            result=updates.load()>0&&root_found.load()?State::Passed:State::Failed;
        }
    }while(false);
    enabled.store(false,std::memory_order_release);
    input_enabled.store(false,std::memory_order_release);
    capture.store(false);release_game("teardown"); // never leave the game without its controller
    auto query=fn<ProtectionQuery>(QueryProtection);
    // Every installed hook gets its removal attempted; a failed one must not
    // short-circuit the rest.
    bool removed=true;
    if(share_hook_store.installed)removed&=remove_hook(share_hook_store,query);
    if(pad_hook_store.installed)removed&=remove_hook(pad_hook_store,query);
    if(update_hook_store.installed)removed&=remove_hook(update_hook_store,query);
    if(!removed)result=State::RemoveFailed;
    // A pending callback may still use Mono and our trampolines. The module and
    // trampolines stay mapped; widget handles were freed after tree removal.
    fn<void(*)(void*)>(ThreadDetach)(thread);
    note("RESULT state=%d updates=%llu pad_polls=%llu share=%u chords=%u doubles=%u game=%d root=%d widgets=%d removed=%d",
        int(result),(unsigned long long)updates.load(),(unsigned long long)pad_polls.load(),share_events.load(),chords.load(),
        double_presses.load(),game_found.load(),root_found.load(),widgets_created.load(),removed);
    publish(result);
    return result;
}
}
extern "C" __attribute__((visibility("default"))) void* elf_main(void*){
    // The party probe (a lab tool) has its own lock: the audio worker holds worker.lock for hours, and a second
    // worker that does not get its lock returns without a word.
    Request peek;
    const bool probe=read_file(worker_dir,"request.bin",peek)&&(peek.mode==Mode::PartyProbe||peek.mode==Mode::SceneProbe||peek.mode==Mode::TileDiscord||peek.mode==Mode::BundleDump||peek.mode==Mode::NativeTileInject);
    char p[256];if(!path(p,sizeof p,worker_dir,probe?"probe.lock":"worker.lock"))return nullptr;
    int lock=open(p,O_CREAT|O_RDWR,0600);if(lock<0)return nullptr;
    if(flock(lock,LOCK_EX|LOCK_NB)){close(lock);return nullptr;}
    if(!read_file(worker_dir,"request.bin",request)||!valid(request,getpid(),OVERLAY_BUILD,request.epoch,now_ms())){
        close(lock);return nullptr;}
    note("START build=%016llx mode=%u",(unsigned long long)request.build,unsigned(request.mode));
    State result=run();
    publish(result);close(lock);return nullptr;
}
