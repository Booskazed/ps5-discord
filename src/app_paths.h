// SPDX-License-Identifier: AGPL-3.0-or-later
// Where this build lives on the console: its title (the app folder is /data/homebrew/<title>) and
// its data folder (session, settings, locks). The defaults are the stock ones. A side-by-side
// edition is built with its own (make EDITION_TITLE_ID=PPSA99073
// EDITION_DATA_DIR=/data/ps5-discord-community, see README.md "Fork notes"), so it never reads or
// writes the stock install's files; the Makefile turns those into these -D flags.
#pragma once

#ifndef APP_TITLE_ID
#define APP_TITLE_ID "PPSA99072"
#endif
#ifndef APP_DATA_DIR
#define APP_DATA_DIR "/data/ps5-discord"
#endif
#define APP_HOMEBREW_DIR "/data/homebrew/" APP_TITLE_ID // the app's /app0 on the console
