/*
 * Author: Lesshy
 */

#include "HookedMethods.hpp"
#include "common.hpp"
#include <iostream>

namespace hooked_methods
{
DEFINE_HOOKED_METHOD(SetRichPresence, bool, const char *pchKey, const char *pchValue);
}
namespace richpresence
{
static settings::Boolean enable{ "steam.presence-enable", "false" };     // Rich Presence
static settings::Boolean marquee{ "steam.presence-marquee", "false" };   // Apply a scrolling effect
static settings::Boolean override{ "steam.presence-override", "false" }; // Override Match  (This makes it so the "Main Menu" effect never happens)
static settings::Int matchstate{ "steam.presence-match", "0" };          // Match Info     4 CHOICES
static settings::Int groupsize{ "steam.presence-group", "6" };           // Party Size
static settings::String custom{ "steam.presence-value", "Cathook" };     // Custom input

void CreateMove()
{
    if (!enable)
    {
        // says "Team Fortress 2" until player leaves/joins a server
        g_ISteamFriends->SetRichPresence("steam_display", "");
    }
    else
    {
        // These are choices for current match
        if (!g_IEngine->IsInGame() && !override)
        {
            // game state is not in a match
            g_ISteamFriends->SetRichPresence("state", "MainMenu");
        }
        else
        {
            // game state is in a match
            g_ISteamFriends->SetRichPresence("state", "PlayingMatchGroup");

            switch (*matchstate)
            {
            case 0: // Special Event
                g_ISteamFriends->SetRichPresence("matchgrouploc", "SpecialEvent");
                break;
            case 1: // Mann Up
                g_ISteamFriends->SetRichPresence("matchgrouploc", "MannUp");
                break;
            case 2: // Competitive
                g_ISteamFriends->SetRichPresence("matchgrouploc", "Competitive6v6");
                break;
            case 3: // Casual
                g_ISteamFriends->SetRichPresence("matchgrouploc", "Casual");
                break;
            case 4: // Boot Camp
                g_ISteamFriends->SetRichPresence("matchgrouploc", "BootCamp");
                break;
            }
        }

        if (*marquee)
        {
            Timer update_rich_presence;
            if (update_rich_presence.test_and_set(5000))
            {
                char temp = (*custom)[0];
                const_cast<std::string&>(*custom).erase(0, 1);
                const_cast<std::string&>(*custom) += temp;
            }
        }

        g_ISteamFriends->SetRichPresence("currentmap", (*custom).c_str());

        // Group Sizing
        g_ISteamFriends->SetRichPresence("steam_player_group_size", groupsize.toString().c_str());
    }
}

// Make sure we register this!
static InitRoutine init([]() { EC::Register(EC::CreateMove, CreateMove, "CM_RichPresence", EC::average); });

} // namespace richpresence
