// DEBUG ONLY: does the "custom music" audio sink (audio/output.cpp, ABI
// recovered from Spotify's PPSA05688, never wired up or tested here) stay
// audible once this app is no longer the focused one? Never ship this build.
// Plays a steady 880 Hz tone through AudioBackend::custom_music for 2
// minutes so a human can background the app and listen. Logs to klog
// (the app cannot write /data).
#ifdef HUI_AUDIO_PROBE

#include "audio/output.hpp"
#include "platform/ps5/system.hpp"

#include <chrono>
#include <cmath>
#include <cstdint>
#include <thread>
#include <vector>

namespace hui::ps5
{
namespace
{

void run()
{
    sys::log("[HUI-AOUT] start: custom-music probe");
    AudioOutput out;
    const bool ok = out.open(AudioBackend::custom_music);
    sys::log("[HUI-AOUT] open custom_music ok=%d last_error=0x%08x", ok,
              static_cast<unsigned>(out.last_error()));
    if (!ok)
    {
        sys::log("[HUI-AOUT] custom_music unavailable, probe stops here");
        return;
    }
    const std::size_t frames = out.grain_frames();
    std::vector<std::int16_t> grain(frames * 2);
    constexpr double kFreq = 880.0, kRate = 48000.0;
    double phase = 0.0;
    int writes = 0, errors = 0;
    const auto until = std::chrono::steady_clock::now() + std::chrono::minutes(2);
    while (std::chrono::steady_clock::now() < until)
    {
        for (std::size_t i = 0; i < frames; ++i)
        {
            const std::int16_t s = static_cast<std::int16_t>(std::sin(phase) * 12000.0);
            grain[i * 2] = s;
            grain[i * 2 + 1] = s;
            phase += 2.0 * M_PI * kFreq / kRate;
        }
        const int rc = out.write(grain.data());
        ++writes;
        if (rc < 0)
        {
            ++errors;
            if (errors <= 5 || errors % 50 == 0)
                sys::log("[HUI-AOUT] write #%d rc=0x%08x", writes, static_cast<unsigned>(rc));
        }
        if (writes % 50 == 0)
            sys::log("[HUI-AOUT] writes=%d errors=%d", writes, errors);
    }
    out.drain();
    out.close();
    sys::log("[HUI-AOUT] done: writes=%d errors=%d", writes, errors);
}

} // namespace

// Runs once the app has had time to settle after startup.
void probe_audio_out_debug()
{
    std::thread([] {
        std::this_thread::sleep_for(std::chrono::seconds(15));
        run();
    }).detach();
}

} // namespace hui::ps5

#endif // HUI_AUDIO_PROBE
