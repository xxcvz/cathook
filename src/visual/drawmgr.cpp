/*
 * drawmgr.cpp
 *
 *  Created on: May 22, 2017
 *      Author: nullifiedcat
 */

#include <MiscTemporary.hpp>
#include <hacks/hacklist.hpp>
#if ENABLE_IMGUI_DRAWING
#include "imgui/imrenderer.hpp"
#elif ENABLE_GLEZ_DRAWING
#include <glez/glez.hpp>
#include <glez/record.hpp>
#include <glez/draw.hpp>
#endif
#include <settings/Bool.hpp>
#include <menu/GuiInterface.hpp>
#include "common.hpp"
#include "visual/drawing.hpp"
#include "hack.hpp"
#include "drawmgr.hpp"

static settings::Boolean info_text{ "hack-info.enable", "true" };
static settings::Boolean info_text_min{ "hack-info.minimal", "false" };

void RenderCheatVisuals()
{
    {
        PROF_SECTION(BeginCheatVisuals)
        BeginCheatVisuals();
    }
    {
        PROF_SECTION(DrawCheatVisuals)
        DrawCheatVisuals();
    }
    {
        PROF_SECTION(EndCheatVisuals)
        EndCheatVisuals();
    }
}
#if ENABLE_GLEZ_DRAWING
glez::record::Record bufferA{};
glez::record::Record bufferB{};

glez::record::Record *buffers[] = { &bufferA, &bufferB };
#endif
int currentBuffer = 0;

void BeginCheatVisuals()
{
#if ENABLE_IMGUI_DRAWING
    im_renderer::bufferBegin();
#elif ENABLE_GLEZ_DRAWING
    buffers[currentBuffer]->begin();
#endif
    ResetStrings();
}

void DrawCheatVisuals()
{
    {
        PROF_SECTION(DRAW_info)
        std::string name_s, reason_s;
        if (*info_text && (!g_IEngine->IsConnected() || g_IEngine->Con_IsVisible()))
        {
            auto color = colors::RainbowCurrent();
            color.a    = 1.0f;
            AddSideString("cathook by nullworks", color);
            if (!*info_text_min)
            {
                AddSideString(hack::GetVersion(), colors::gui); // GitHub commit and date
                AddSideString(hack::GetType(), colors::gui);    // Compile type
#if ENABLE_GUI
                AddSideString("Press '" + open_gui_button.toString() + "' key to open/close cheat menu.", colors::gui);
                AddSideString("Use mouse to navigate in menu.", colors::gui);
#endif
            }
        }
    }
    if (spectator_target)
        AddCenterString("Press SPACE to stop spectating");
    {
        PROF_SECTION(DRAW_WRAPPER)
        EC::run(EC::Draw);
    }
    if (CE_GOOD(LOCAL_E))
    {
        PROF_SECTION(DRAW_skinchanger)
        hacks::skinchanger::DrawText();
        Prediction_PaintTraverse();
    }
    {
        PROF_SECTION(DRAW_strings)
        DrawStrings();
    }
#if ENABLE_GUI
    {
        PROF_SECTION(DRAW_GUI)
        gui::draw();
    }
#endif
}

void EndCheatVisuals()
{
#if ENABLE_GLEZ_DRAWING
    buffers[currentBuffer]->end();
#endif
#if ENABLE_GLEZ_DRAWING || ENABLE_IMGUI_DRAWING
    currentBuffer = !currentBuffer;
#endif
}

void DrawCache()
{
#if ENABLE_GLEZ_DRAWING
    buffers[!currentBuffer]->replay();
#endif
}
