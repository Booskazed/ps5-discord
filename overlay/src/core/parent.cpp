// SPDX-License-Identifier: GPL-3.0-or-later
#include "protocol.hpp"
#include "stable_shellui_injector.hpp"
#include <ps5/kernel.h>
#include <ps5/nid.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <pthread.h>
#include <atomic>
#include <signal.h>
#include <fcntl.h>
#include <csignal>
#include <cstdlib>
#include <cerrno>
#include <cstdarg>
#ifndef OVERLAY_BUILD
#define OVERLAY_BUILD 0ULL
#endif
#ifndef OVERLAY_MODE
#define OVERLAY_MODE 0
#endif
#if OVERLAY_MODE<0||OVERLAY_MODE>13
#error "OVERLAY_MODE must be 0 resolve, 1 observe, 2 widget, 3 input, 4 restart, 5 service, 6 audiotest, 7 audiorelay, 8 partyprobe, 9 sceneprobe, 10 tilediscord, 11 bundledump, 12 nativetileinject, 13 cctileinject"
#endif
extern "C" {extern const unsigned char overlay_worker_blob[];extern const unsigned int overlay_worker_blob_size;
volatile sig_atomic_t overlay_abort_requested=0;
int sceKernelGetAppInfo(pid_t,void*);}
using namespace overlay;
// elfldr deploys every payload as payload.elf, so each mode keeps its own USB
// xlog to keep runs attributable (workspace payload discipline).
static constexpr const char* mode_names[]{"resolve","observe","widget","input","restart","service","audiotest","audiorelay","partyprobe","sceneprobe","tilediscord","bundledump","nativetileinject","cctileinject"};
static FILE* logfile=nullptr,*usblog=nullptr;
static void note(const char* fmt,...){
    char line[512];va_list ap;va_start(ap,fmt);std::vsnprintf(line,sizeof line,fmt,ap);va_end(ap);
    FILE* outputs[]={stderr,logfile,usblog};for(auto f:outputs)if(f){std::fprintf(f,"[overlay-loader pid=%d ms=%llu] %s\n",getpid(),(unsigned long long)now_ms(),line);std::fflush(f);}
}
static bool target(Request& r){
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PROC,0};std::size_t n=0;
    if(sysctl(mib,4,nullptr,&n,nullptr,0)||!n||n>16*1024*1024)return false;
    auto* data=static_cast<unsigned char*>(std::malloc(n));if(!data)return false;unsigned matches=0;
    if(!sysctl(mib,4,data,&n,nullptr,0))for(std::size_t at=0;at+sizeof(kinfo_proc)<=n;){
        auto* info=reinterpret_cast<kinfo_proc*>(data+at);
        if(info->ki_structsize<int(sizeof(kinfo_proc))||std::size_t(info->ki_structsize)>n-at)break;
        if(!std::strcmp(info->ki_comm,"SceShellUI")){r.pid=info->ki_pid;r.epoch=std::uint64_t(info->ki_start.tv_sec)*1000000+info->ki_start.tv_usec;++matches;}
        at+=info->ki_structsize;
    }
    std::free(data);return matches==1&&r.pid>1&&r.epoch;
}
// The firmwares this overlay may run on, as kern.sdk_version >> 16 and as the kernel's firmware
// version. 13.00 is where the hook offsets, colours, button bits and Mono signatures were measured.
// 13.60 is allowed explicitly: worker.cpp still checks every method and signature and refuses
// cleanly if SceShellUI differs, and every other refusal below is unchanged.
static const std::uint32_t allowed_sdk[]={0x1300U,0x1360U};
static const std::uint32_t allowed_fw[]={0x13000000U,0x13600000U};
static bool allowed(const std::uint32_t* list,std::size_t n,std::uint32_t v){
    for(std::size_t i=0;i<n;++i)if(list[i]==v)return true;
    return false;
}
static int run(){
    // kabuki-style SDK probe: works without the kernel bridge (kern.sdk_version).
    std::uint32_t sdk=0;std::size_t sdk_len=sizeof sdk;
    bool have_sdk=sysctlbyname("kern.sdk_version",&sdk,&sdk_len,nullptr,0)==0&&sdk_len==sizeof sdk;
    auto fw=kernel_get_fw_version();
    note("START build=%016llx firmware=%08x sdk=%08x mode=%s",
        (unsigned long long)OVERLAY_BUILD,fw,have_sdk?sdk:0,mode_names[OVERLAY_MODE]);
    if(have_sdk){if(!allowed(allowed_sdk,sizeof allowed_sdk/sizeof*allowed_sdk,sdk>>16)){note("REFUSED: only FW13.00 and FW13.60 are allowed (sdk=%08x)",sdk);return 1;}}
    else if(fw&&!allowed(allowed_fw,sizeof allowed_fw/sizeof*allowed_fw,fw)){note("REFUSED: only FW13.00 and FW13.60 are allowed (firmware=%08x)",fw);return 1;}
    else note("NOTE fw unknown (kernel query and kern.sdk_version both unavailable); relying on method/signature checks");
    Request r;r.build=OVERLAY_BUILD;r.mode=static_cast<Mode>(OVERLAY_MODE);
    if(!target(r)){note("REFUSED: unique ShellUI PID/start identity missing");return 1;}
#if OVERLAY_MODE==4
    // Restart mode is the documented rollback: the system respawns SceShellUI,
    // giving the next attempt a fresh PID/start identity.
    note("RESTART killing SceShellUI pid=%d epoch=%llu",r.pid,(unsigned long long)r.epoch);
    if(kill(r.pid,SIGKILL)){note("RESTART kill failed errno=%d",errno);return 1;}
    note("RESTART done; expect home screen to reload");
    return 0;
#endif
    // AudioTest/AudioRelay/PartyProbe/SceneProbe never install a hook (no
    // prepare_update_hook call at all): unlike every other mode, retrying
    // one on the same ShellUI instance carries none of the risk this
    // one-attempt marker exists to bound, so they are exempt from it.
    // CCTileInject does install hooks, but refuses cleanly when the prologue is
    // already detoured (cc_prehooked), so a retry can never double-hook; it is
    // exempt too, which lets the JS be re-armed after a stop without a restart.
    const bool one_shot_only=r.mode!=Mode::AudioTest&&r.mode!=Mode::AudioRelay&&r.mode!=Mode::PartyProbe&&r.mode!=Mode::SceneProbe&&r.mode!=Mode::TileDiscord&&r.mode!=Mode::BundleDump&&r.mode!=Mode::NativeTileInject&&r.mode!=Mode::CCTileInject;
    Attempt prior;
    if(one_shot_only&&read_file(parent_dir,"attempt.bin",prior)&&prior.signature==magic&&prior.pid==r.pid&&prior.epoch==r.epoch){
        note("REFUSED: one attempt already recorded for this ShellUI instance; inspect evidence, do not delete marker to retry");return 1;}
    std::uint32_t mono=0,kernel=0;
    if(kernel_dynlib_handle(r.pid,"libmonosgen-2.0.sprx",&mono)||!mono){
        if(kernel_dynlib_handle(r.pid,"libmonosgen-2.0.0.sprx",&mono)||!mono){note("REFUSED Mono module missing");return 1;}}
    if(kernel_dynlib_handle(r.pid,"libkernel_sys.sprx",&kernel)||!kernel){note("REFUSED kernel module missing");return 1;}
    std::uint32_t web=0,libc=0,system=0,audioout=0,audioin=0,userservice=0;
    (void)kernel_dynlib_handle(r.pid,"libkernel_web.sprx",&web);
    // Lab (mic from ShellUI): absent from ShellUI's module list is a valid answer; logged, not fatal.
    if(kernel_dynlib_handle(r.pid,"libSceAudioIn.sprx",&audioin)||!audioin){audioin=0;note("lab: libSceAudioIn is not loaded in ShellUI");}
    else note("lab: libSceAudioIn handle %u",unsigned(audioin));
    if(kernel_dynlib_handle(r.pid,"libSceUserService.sprx",&userservice)||!userservice){userservice=0;note("lab: libSceUserService is not loaded in ShellUI");}
    (void)kernel_dynlib_handle(r.pid,"libSceSystemService.sprx",&system);
    (void)kernel_dynlib_handle(r.pid,"libSceLibcInternal.sprx",&libc);
    // Required only for Mode::AudioTest, but resolved for every mode (cheap,
    // and ShellUI always has its own system-sound output loaded) so the
    // generic loop below need not special-case it by mode.
    if(kernel_dynlib_handle(r.pid,"libSceAudioOut.sprx",&audioout)||!audioout){
        note("REFUSED libSceAudioOut module missing");return 1;}
    for(unsigned i=0;i<FunctionCount;i++){
        std::uint64_t address_value=0;
        if(optional(i)){
            if(i==RnpsVerifyDecrypt){
                // Lab (Mode::BundleDump): the RNPS bundle loader's verify+decrypt export, known only by NID.
                std::uint32_t rnps=0;
                if(kernel_dynlib_handle(r.pid,"libSceRnpsBundle.sprx",&rnps)||!rnps)(void)kernel_dynlib_handle(r.pid,"libSceRnpsBundle.prx",&rnps);
                if(rnps)address_value=kernel_dynlib_resolve(r.pid,rnps,symbols[i]);
                if(!address(address_value)){note("optional rnps %s missing",symbols[i]);address_value=0;}
                else note("resolved rnps %s in module %u",symbols[i],unsigned(rnps));
                r.functions[i]=address_value;continue;
            }
            // The mic and user-service lab functions live in their own modules, not in SystemService.
            if(i==IpmiConfigInit||i==IpmiClientCreate){
                // PartyProbe lab: libSceIpmi is already loaded in ShellUI; these exports are only known by NID.
                std::uint32_t ipmi=0;
                if(!kernel_dynlib_handle(r.pid,"libSceIpmi.sprx",&ipmi)&&ipmi)address_value=kernel_dynlib_resolve(r.pid,ipmi,symbols[i]);
                if(!address(address_value)){note("optional ipmi %s missing",symbols[i]);address_value=0;}
                else note("resolved ipmi %s in module %u",symbols[i],unsigned(ipmi));
                r.functions[i]=address_value;continue;
            }
            if(i==MonoClassVtable||i==MonoFieldStaticGet||i==MonoNestedTypes||i==MonoClassImage){
                // Tile lab: standard Mono embedding exports; a miss only disables the static-field read.
                address_value=kernel_dynlib_dlsym(r.pid,mono,symbols[i]);
                if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,mono,nid);}
                if(!address(address_value)){note("optional %s missing",symbols[i]);address_value=0;}
                else note("resolved %s in Mono",symbols[i]);
                r.functions[i]=address_value;continue;
            }
            if(i==KernelLoadStartModule||i==KernelDlsym||i==KernelSysctl){
                // PartyProbe lab: libkernel's own loader entry points, whichever flavour ShellUI has loaded.
                std::uint32_t plain=0;(void)kernel_dynlib_handle(r.pid,"libkernel.sprx",&plain);
                const std::uint32_t candidates[3]={kernel,plain,web};
                for(std::uint32_t handle:candidates){
                    if(!handle)continue;
                    address_value=kernel_dynlib_dlsym(r.pid,handle,symbols[i]);
                    if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,handle,nid);}
                    if(address(address_value)){note("resolved %s via module %u",symbols[i],unsigned(handle));break;}
                }
                if(!address(address_value)){note("optional %s missing",symbols[i]);address_value=0;}
                r.functions[i]=address_value;continue;
            }
            const std::uint32_t home=(i==AudioInOpen||i==AudioInInput||i==AudioInClose)?audioin:
                                     (i==UserGetForegroundUser)?userservice:system;
            if(home){address_value=kernel_dynlib_dlsym(r.pid,home,symbols[i]);
                if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,home,nid);}}
            if(!address(address_value)){note("optional %s missing: the overlay cannot hold the game",symbols[i]);address_value=0;}
            r.functions[i]=address_value;continue;
        }
        if(i==AudioOutInit||i==AudioOutOpen||i==AudioOutOutput||i==AudioOutClose){
            address_value=kernel_dynlib_dlsym(r.pid,audioout,symbols[i]);
            if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,audioout,nid);}
        } else if(i==TargetMmap||i==TargetMunmap){
            // Plain mmap/munmap live in whichever BSD-ish module ShellUI loaded.
            const std::uint32_t candidates[3]={web,libc,kernel};
            for(std::uint32_t handle:candidates){
                if(!handle)continue;
                address_value=kernel_dynlib_dlsym(r.pid,handle,symbols[i]);
                if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,handle,nid);}
                if(address(address_value)){note("resolved %s via module %u",symbols[i],handle);break;}
            }
        } else {
            auto handle=(i==QueryProtection||i==TargetMprotect)?kernel:mono;
            address_value=kernel_dynlib_dlsym(r.pid,handle,symbols[i]);
            if(!address_value){char nid[12]{};if(nid_encode(symbols[i],nid))address_value=kernel_dynlib_resolve(r.pid,handle,nid);}
        }
        if(!address(address_value)){note("REFUSED: missing %s",symbols[i]);return 1;}r.functions[i]=address_value;
    }
    {alignas(16) unsigned char info[256]{};
     if(sceKernelGetAppInfo(r.pid,info)==0)std::memcpy(&r.shell_app,info,sizeof r.shell_app);
     note("ShellUI app id 0x%08x",unsigned(r.shell_app));}
    r.token=(now_ms()<<17)^std::uint64_t(getpid());
    // AudioRelay keeps running for as long as the app's relay connection
    // stays up (minutes); everything else is a short, bounded one-shot.
    r.deadline_ms=now_ms()+(r.mode==Mode::AudioRelay||r.mode==Mode::NativeTileInject||r.mode==Mode::CCTileInject?86400000:(r.mode==Mode::PartyProbe||r.mode==Mode::SceneProbe||r.mode==Mode::TileDiscord||r.mode==Mode::BundleDump)?600000:75000);
    if(r.mode==Mode::PartyProbe){
        // Read-only census (lab): which party/voice libraries ShellUI already has loaded. Logged, never fatal.
        static const char* const party_modules[]={"libSceProprietaryVoiceChatHelper.native.sprx","libSceVoiceChat.sprx",
            "libSceNpParty.sprx","libSceIpmi.sprx","libSceNpManager.sprx","libSceVoice.sprx","libSceVoiceQoS.sprx"};
        for(const char* name:party_modules){
            std::uint32_t handle=0;const int rc=kernel_dynlib_handle(r.pid,name,&handle);
            note("census %s rc=%d handle=%u",name,rc,unsigned(handle));}
    }
    if(!write_file(parent_dir,"request.bin",r)){note("request write failed");return 1;}
    if(one_shot_only){
        Attempt a;a.pid=r.pid;a.epoch=r.epoch;a.token=r.token;
        if(!write_file(parent_dir,"attempt.bin",a))return 1;}
    auto result=common_fps::ps5::inject_shellui_stable(r.pid,overlay_worker_blob,overlay_worker_blob_size);
    note("LOADER target=%d epoch=%llu mapped=%u thread=%u detached=%u auth_restored=%u unresolved=%u first=%s",r.pid,
        (unsigned long long)r.epoch,result.elf_loaded,result.pthread_create_ok,result.detached,result.auth_restored,result.imports_unresolved,
        result.first_unresolved?result.first_unresolved:"");
    if(!result.elf_loaded||!result.pthread_create_ok||!result.detached||!result.auth_restored||result.imports_unresolved)return 1;
    // The audio worker runs on its own inside ShellUI (its own lock, heartbeat and 24 h window): this loader is
    // done, so it frees parent.lock and a later launch (the core sends the worker again if the heartbeat goes stale) works.
    if(r.mode==Mode::AudioRelay){note("LOADER: audio worker injected, loader exits");return 0;}
    if(r.mode==Mode::PartyProbe){note("LOADER: party probe injected, loader exits (see worker.log)");return 0;}
    if(r.mode==Mode::SceneProbe){note("LOADER: scene probe injected, loader exits (see worker.log)");return 0;}
    if(r.mode==Mode::TileDiscord){note("LOADER: tile-discord injected, loader exits (see worker.log)");return 0;}
    if(r.mode==Mode::BundleDump){note("LOADER: bundle dump injected, loader exits (see worker.log)");return 0;}
    if(r.mode==Mode::NativeTileInject){note("LOADER: native tile inject started, loader exits (see worker.log)");return 0;}
    if(r.mode==Mode::CCTileInject){note("LOADER: cc tile inject started, loader exits (see worker.log)");return 0;}
    int previous=999;
#if OVERLAY_MODE==5
    // Service: no fixed end. A heartbeat every second keeps the worker; on SIGTERM (or a
    // worker that stops reporting) we stop beating, ask it to stop and wait for teardown.
    std::uint64_t last_status=now_ms(),stop_at=0;
    for(;;){
        const std::uint64_t now=now_ms();
        if(!stop_at&&!overlay_abort_requested){Keepalive k;k.token=r.token;k.at_ms=now;(void)write_file(parent_dir,"keepalive.bin",k);}
        Status s;
        if(read_file(parent_dir,"status.bin",s)&&s.signature==magic&&s.token==r.token&&s.at_ms<=now+1000&&now<=s.at_ms+2000){
            last_status=now;
            if(int(s.state)!=previous){note("STATE=%d updates=%llu widgets=%d/%d text=%u pad=%llu chords=%u hooks=%d/%d",
                int(s.state),(unsigned long long)s.updates,s.widgets_created,s.widget_removed,s.text_updates,
                (unsigned long long)s.pad_polls,s.chords,s.hook_removed,s.hook_installed);previous=int(s.state);}
            if(s.state==State::Passed&&s.hook_installed&&s.hook_removed==s.hook_installed)return 0;
            if(int(s.state)<0)return 1;}
        if(!stop_at&&(overlay_abort_requested||now-last_status>15000)){
            note(overlay_abort_requested?"SERVICE stop requested":"SERVICE worker stopped reporting");
            (void)write_file(parent_dir,"stop.bin",r.token);stop_at=now;}
        if(stop_at&&now-stop_at>10000){note("SERVICE teardown not confirmed; inspect worker.log");return 1;}
        usleep(250000);
    }
#endif
    while(now_ms()<r.deadline_ms&&!overlay_abort_requested){
        Status s;if(read_file(parent_dir,"status.bin",s)&&s.signature==magic&&s.token==r.token&&s.at_ms<=now_ms()+1000&&now_ms()<=s.at_ms+2000){
            if(int(s.state)!=previous){note("STATE=%d updates=%llu game=%d root=%d widgets=%d/%d text=%u pad=%llu share=%u chords=%u doubles=%u hooks=%d/%d",
                int(s.state),(unsigned long long)s.updates,s.game_found,s.root_found,s.widgets_created,s.widget_removed,
                s.text_updates,(unsigned long long)s.pad_polls,s.share_events,s.chords,s.double_presses,s.hook_removed,s.hook_installed);
                previous=int(s.state);}
            if(s.state==State::Resolved)return 0;
            if(s.state==State::Passed&&s.hook_installed&&s.hook_removed==s.hook_installed)return 0;
            if(int(s.state)<0)return 1;
        }
        usleep(100000);
    }
    (void)write_file(parent_dir,"stop.bin",r.token);note("deadline/stop; worker has independent deadline; inspect worker.log");return 1;
}
static void stop(int){overlay_abort_requested=1;}
#if OVERLAY_MODE!=5 // the service runs its loader in its own process (main)
static void* thread_main(void*){return reinterpret_cast<void*>(std::intptr_t(run()));}
#endif
extern "C" int sceKernelSetProcessName(const char* name);
int main(){
    // Payload managers list elfldr's processes as payload.elf: say whose this one is.
#if OVERLAY_MODE==5
    sceKernelSetProcessName("discord-overlay.elf");
#elif OVERLAY_MODE==4
    sceKernelSetProcessName("discord-overlay-restart.elf");
#endif
    if(mkdir(parent_dir,0700)&&errno!=EEXIST)return 1;
    char p[256];path(p,sizeof p,parent_dir,"parent.lock");int lock=open(p,O_CREAT|O_RDWR,0600);
#if OVERLAY_MODE!=4 // restart works with a service running: its worker dies with ShellUI, its loader then stops
    if(lock<0||flock(lock,LOCK_EX|LOCK_NB))return 1;
#endif
    path(p,sizeof p,parent_dir,"loader.log");logfile=std::fopen(p,"a");
    char usb[96];std::snprintf(usb,sizeof usb,"/mnt/usb0/discord-overlay-%s.log",mode_names[OVERLAY_MODE]);
    usblog=std::fopen(usb,"a");
    std::signal(SIGTERM,stop);std::signal(SIGINT,stop);
#if OVERLAY_MODE==5
    // Service: one process (it was a parent watching a forked loader; payload managers listed
    // both as discord-overlay.elf). The loader runs in a thread; this one is its watchdog and
    // ends the whole process if the loader hangs, which also ends its tracing of ShellUI.
    static std::atomic<int> loader_done{0};static std::intptr_t loader_result=1;
    struct Loader{static void* go(void*){loader_result=std::intptr_t(run());loader_done.store(1);return nullptr;}};
    auto began=now_ms();
    {pthread_attr_t attr;pthread_t loader;if(pthread_attr_init(&attr))return 1;
        int rc=pthread_attr_setstacksize(&attr,2*1024*1024);if(!rc)rc=pthread_create(&loader,&attr,Loader::go,nullptr);
        pthread_attr_destroy(&attr);if(rc)return 1;
        for(bool asked=false;!loader_done.load();usleep(50000)){
            // The watchdog only counts while the worker is not reporting.
            {Status s;if(read_file(parent_dir,"status.bin",s)&&s.signature==magic&&s.state==State::Observing&&
                 s.at_ms<=now_ms()+1000&&now_ms()<=s.at_ms+2000&&!overlay_abort_requested)began=now_ms();}
            auto elapsed=now_ms()-began;
            if(!asked&&elapsed>=80000){overlay_abort_requested=1;asked=true;} // the loader stops beating, asks the worker to stop
            if(elapsed>=90000){note("WATCHDOG: loader stuck; ending the service process");std::_Exit(1);}}
        pthread_join(loader,nullptr);}
    const int status=int(loader_result)<<8; // as a child's exit status was logged
#else
    auto began=now_ms();pid_t child=fork();if(child<0)return 1;
    if(!child){pthread_attr_t attr;pthread_t worker;if(pthread_attr_init(&attr))_exit(1);
        int rc=pthread_attr_setstacksize(&attr,2*1024*1024);if(!rc)rc=pthread_create(&worker,&attr,thread_main,nullptr);
        pthread_attr_destroy(&attr);if(rc)_exit(1);void* result=nullptr;if(pthread_join(worker,&result))_exit(1);_exit(int(reinterpret_cast<std::intptr_t>(result)));}
    int status=0;bool signaled=false;
    for(;;){auto rc=waitpid(child,&status,WNOHANG);if(rc==child)break;if(rc<0&&errno!=EINTR)return 1;
#if OVERLAY_MODE==5
        // Service lives on: the watchdog only counts while the worker is not reporting.
        {Status s;if(read_file(parent_dir,"status.bin",s)&&s.signature==magic&&s.state==State::Observing&&
             s.at_ms<=now_ms()+1000&&now_ms()<=s.at_ms+2000&&!overlay_abort_requested)began=now_ms();}
#endif
        auto elapsed=now_ms()-began;if(!signaled&&(overlay_abort_requested||elapsed>=80000)){kill(child,SIGTERM);signaled=true;}
        if(elapsed>=90000){note("WATCHDOG: killing only owned loader worker; inspect ShellUI state before any retry");kill(child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}break;}usleep(50000);}
#endif
    note("worker status=0x%x",status);close(lock);if(logfile)std::fclose(logfile);if(usblog)std::fclose(usblog);
    return WIFEXITED(status)?WEXITSTATUS(status):1;
}
