/*
 * ESP.cpp
 *
 *  Created on: Oct 6, 2016
 *      Author: nullifiedcat
 */

#include <hacks/ESP.hpp>
#include <PlayerTools.hpp>
#include <settings/Bool.hpp>
#include "common.hpp"
#include "soundcache.hpp"

namespace hacks::esp
{
static settings::Boolean enable{ "esp.enable", "false" };
static settings::Int max_dist{ "esp.range", "4096" };

static settings::Int box_esp{ "esp.box.mode", "2" };
static settings::Int box_corner_size_height{ "esp.box.corner-size.height", "10" };
static settings::Int box_corner_size_width{ "esp.box.corner-size.width", "10" };
static settings::Boolean box_3d_player{ "esp.box.player-3d", "false" };
static settings::Boolean box_3d_building{ "esp.box.building-3d", "false" };

static settings::Boolean draw_bones{ "esp.bones", "false" };
static settings::Float bones_thickness{ "esp.bones.thickness", "0.5" };
static settings::Boolean bones_color{ "esp.bones.color", "false" };

static settings::Int healthbar{ "esp.health-bar", "3" };
static settings::Int sightlines{ "esp.sightlines", "0" };
static settings::Int esp_text_position{ "esp.text-position", "0" };
static settings::Int esp_expand{ "esp.expand", "0" };
static settings::Boolean vischeck{ "esp.vischeck", "true" };
static settings::Boolean hide_invis{ "esp.hide-invis", "false" };
static settings::Boolean legit{ "esp.legit", "false" };

static settings::Boolean local_esp{ "esp.show.local", "true" };
static settings::Boolean buildings{ "esp.show.buildings", "true" };
static settings::Boolean team_buildings{ "esp.show.team-buildings", "false" };
static settings::Boolean teammates{ "esp.show.teammates", "true" };
static settings::Boolean npc{ "esp.show.npc", "true" };

static settings::Boolean show_weapon{ "esp.info.weapon", "false" };
static settings::Boolean show_distance{ "esp.info.distance", "true" };
static settings::Boolean show_buster_radius{ "esp.info.buster-radius", "true" };
static settings::Boolean show_health{ "esp.info.health", "true" };
static settings::Boolean show_name{ "esp.info.name", "true" };
static settings::Boolean show_class{ "esp.info.class", "true" };
static settings::Boolean show_conditions{ "esp.info.conditions", "true" };
static settings::Boolean show_ubercharge{ "esp.info.ubercharge", "true" };
static settings::Boolean powerup_esp{ "esp.info.powerup", "true" };

static settings::Boolean item_esp{ "esp.item.enable", "true" };
static settings::Boolean item_ammo_packs{ "esp.item.ammo", "false" };
static settings::Boolean item_health_packs{ "esp.item.health", "true" };
// static settings::Boolean item_powerups{ "esp.item.powerup", "true" };
static settings::Boolean item_money{ "esp.item.money", "true" };
static settings::Boolean item_spellbooks{ "esp.item.spellbook", "true" };
static settings::Boolean item_explosive{ "esp.item.explosive", "true" };
static settings::Boolean item_crumpkin{ "esp.item.crumpkin", "true" };
static settings::Boolean item_gargoyle{ "esp.item.gargoyle", "true" };
static settings::Boolean item_objectives{ "esp.item.objectives", "false" };

static settings::Boolean proj_esp{ "esp.projectile.enable", "false" };
static settings::Boolean proj_enemy{ "esp.projectile.enemy-only", "true" };

static settings::Boolean entity_info{ "esp.debug.entity", "false" };
static settings::Boolean entity_model{ "esp.debug.model", "false" };
static settings::Boolean entity_id{ "esp.debug.id", "true" };

// Forward declarations
class ESPData
{
public:
    int string_count{ 0 };
    boost::unordered_flat_map<std::string, rgba_t> strings{};
    rgba_t color{ colors::empty };
    bool needs_paint{ false };
    bool has_collide{ false };
    Vector collide_max{ 0, 0, 0 };
    Vector collide_min{ 0, 0, 0 };
    bool transparent{ false };
};

boost::unordered_flat_map<u_int16_t, ESPData> data;
inline void AddEntityString(CachedEntity *entity, const std::string &string, const rgba_t &color = colors::empty)
{
    ESPData &entity_data = data[entity->m_IDX];
    if (entity_data.strings.try_emplace(string, color).second)
        ++(entity_data.string_count);
    entity_data.needs_paint = true;
}

inline bool HitboxUpdate(CachedEntity *ent)
{
    auto hit = ent->hitboxes.GetHitbox(0);
    if (!hit)
        return false;
    Vector hbm, hbx;
    if (!draw::WorldToScreen(hit->min, hbm) || !draw::WorldToScreen(hit->max, hbx))
        return false;
}

// Sets an entitys esp color
void SetEntityColor(CachedEntity *entity, const rgba_t &color)
{
    data[entity->m_IDX].color = color;
}

inline void RepaintEnt(CachedEntity *ent, float distance)
{
    rgba_t color = colors::EntityF(ent);
    if (RAW_ENT(ent)->IsDormant())
    {
        color.r *= 0.5f;
        color.g *= 0.5f;
        color.b *= 0.5f;
    }
    // If show distance, add string here
    if (show_distance)
        AddEntityString(ent, format(int(distance / 64 * 1.22f), 'm'));
    if (show_buster_radius && IsSentryBuster(ent))
    {
        // range check with a bit extra just to be safe
        if (distance < 310)
            AddEntityString(ent, "DANGER ZONE!", colors::FromRGBA8(255.0f, 0.0f, 0.0f, 255.0f));
        else
            AddEntityString(ent, "SAFE ZONE", colors::FromRGBA8(0.0f, 255.0f, 0.0f, 255.0f));
    }
    SetEntityColor(ent, color);
}

void ResetEntityStrings(bool full_clear);
// Entity Processing
void _FASTCALL ProcessEntity(CachedEntity *ent);
void ProcessEntityPT();

void _FASTCALL ShowConditions(CachedEntity *ent);
// helper funcs
void _FASTCALL Draw3DBox(CachedEntity *ent, const rgba_t &clr);
void _FASTCALL DrawBox(CachedEntity *ent, const rgba_t &clr);
void BoxCorners(int minx, int miny, int maxx, int maxy, const rgba_t &color, bool transparent);
bool GetCollide(CachedEntity *ent);

// Storage vars for entities that need to be re-drawn
std::vector<std::pair<CachedEntity *, float>> entities_need_repaint{};

// Vars to store what bones connect to what
const std::string bonenames_leg_r[]  = { "bip_foot_R", "bip_knee_R", "bip_hip_R" };
const std::string bonenames_leg_l[]  = { "bip_foot_L", "bip_knee_L", "bip_hip_L" };
const std::string bonenames_bottom[] = { "bip_hip_R", "bip_pelvis", "bip_hip_L" };
const std::string bonenames_spine[]  = { "bip_pelvis", "bip_spine_0", "bip_spine_1", "bip_spine_2", "bip_spine_3", "bip_neck", "bip_head" };
const std::string bonenames_arm_r[]  = { "bip_upperArm_R", "bip_lowerArm_R", "bip_hand_R" };
const std::string bonenames_arm_l[]  = { "bip_upperArm_L", "bip_lowerArm_L", "bip_hand_L" };
const std::string bonenames_up[]     = { "bip_upperArm_R", "bip_spine_3", "bip_upperArm_L" };

class bonelist_s
{
private:
    boost::unordered_flat_map<std::string, int> bones{};
    std::vector<int> leg_r;
    std::vector<int> leg_l;
    std::vector<int> bottom;
    std::vector<int> spine;
    std::vector<int> arm_r;
    std::vector<int> arm_l;
    std::vector<int> up;

public:
    bool setup{ false };
    bool success{ false };
    void Setup(const studiohdr_t *hdr);
    void _FASTCALL DrawBoneList(const matrix3x4_t *bones, std::vector<int> const &in, int size, const rgba_t &color);
    void _FASTCALL Draw(CachedEntity *ent, const rgba_t &color);
};

void bonelist_s::Setup(const studiohdr_t *hdr)
{
    if (!hdr)
    {
        setup   = false;
        success = false;
        return;
    }
    bones.clear();
    for (int i = 0; i < hdr->numbones; ++i)
        bones.emplace(std::string(hdr->pBone(i)->pszName()), i);
    for (const auto &spine_str : bonenames_spine)
        if (bones.contains(spine_str))
            spine.emplace_back(bones.at(spine_str));
    for (int i = 0; i < 3; ++i)
    {
        if (bones.contains(bonenames_arm_l[i]))
            arm_l.emplace_back(bones.at(bonenames_arm_l[i]));
        if (bones.contains(bonenames_up[i]))
            up.emplace_back(bones.at(bonenames_up[i]));
        if (bones.contains(bonenames_arm_r[i]))
            arm_r.emplace_back(bones.at(bonenames_arm_r[i]));
        if (bones.contains(bonenames_bottom[i]))
            bottom.emplace_back(bones.at(bonenames_bottom[i]));
        if (bones.contains(bonenames_leg_l[i]))
            leg_l.emplace_back(bones.at(bonenames_leg_l[i]));
        if (bones.contains(bonenames_leg_r[i]))
            leg_r.emplace_back(bones.at(bonenames_leg_r[i]));
    }

    success = true;
    setup   = true;
}

void _FASTCALL bonelist_s::DrawBoneList(const matrix3x4_t *bones, std::vector<int> const &in, int size, const rgba_t &color)
{
    Vector last_screen;
    Vector current_screen;
    for (int i = 0; i < size; ++i)
    {
        const auto &bone = bones[in[i]];
        Vector position(bone[0][3], bone[1][3], bone[2][3]);
        if (!draw::WorldToScreen(position, current_screen))
            return;
        if (i > 0)
            draw::Line(last_screen.x, last_screen.y, current_screen.x - last_screen.x, current_screen.y - last_screen.y, color, *bones_thickness);
        last_screen = current_screen;
    }
}

void _FASTCALL bonelist_s::Draw(CachedEntity *ent, const rgba_t &color)
{
    const model_t *model = RAW_ENT(ent)->GetModel();
    if (!model)
        return;

    studiohdr_t *hdr = g_IModelInfo->GetStudiomodel(model);

    if (!setup)
        Setup(hdr);
    if (!success)
        return;
    const auto &bones = ent->hitboxes.GetBones();
    DrawBoneList(bones, leg_r, leg_r.size(), color);
    DrawBoneList(bones, leg_l, leg_l.size(), color);
    DrawBoneList(bones, bottom, bottom.size(), color);
    DrawBoneList(bones, spine, spine.size(), color);
    DrawBoneList(bones, arm_r, arm_r.size(), color);
    DrawBoneList(bones, arm_l, arm_l.size(), color);
    DrawBoneList(bones, up, up.size(), color);
    leg_r.clear();
    leg_l.clear();
    bottom.clear();
    spine.clear();
    arm_r.clear();
    arm_l.clear();
    up.clear();
}

// These are strings that never change and should only be constructed once
const std::string dormant_str        = "DORMANT";
const std::string jarated_str        = "JARATED";
const std::string milked_str         = "MILKED";
const std::string burn_str           = "BURN";
const std::string bleed_str          = "BLEED";
const std::string taunting_str       = "TAUNT";
const std::string revving_str        = "REV";
const std::string drawn_str          = "DRAWN";
const std::string slowed_str         = "SLOWDOWN";
const std::string zooming_str        = "ZOOMED";
const std::string crit_str           = "CRITS";
const std::string blast_p_str        = "BLAST RESIST";
const std::string blast_a_str        = "BLAST RESIST CHARGE";
const std::string fire_p_str         = "FIRE RESIST";
const std::string fire_a_str         = "FIRE RESIST CHARGE";
const std::string bullet_p_str       = "BULLET RESIST";
const std::string bullet_a_str       = "BULLET RESIST CHARGE";
const std::string invulnerable_str   = "INVULNERABLE";
const std::string ready_ringer_str   = "DEADRINGER OUT";
const std::string cloaked_str        = "CLOAKED";
const std::string in_ringer_str      = "DEADRINGER";
const std::string disguised_str      = "DISGUISE";
const std::string gassed_str         = "GASSED";
const std::string objective_str      = "Objective";
const std::string tp_ready_str       = "READY";
const std::string sapped_str         = "SAPPED";
const std::string controlled_str     = "CONTROLLED";
const std::string disabled_str       = "DISABLED";
const std::string teleporter_str     = "Tele Entrance";
const std::string teleporterexit_str = "Tele Exit";
const std::string sentry_str         = "Sentry";
const std::string dispenser_str      = "Dispenser";
const std::string rare_spell_str     = "Rare Spell";
const std::string spell_str          = "Spell";
const std::string ammopack_str       = "Ammopack";
const std::string healthpack_str     = "Healthpack";
const std::string mvm_money_str      = "Money";
const std::string tank_str           = "Tank";
const std::string merasmus_str       = "Merasmus";
const std::string monoculus_str      = "Monoculus";
const std::string horsemann_str      = "Horsemann";
const std::string skeleton_str       = "Skeleton";
// const std::string ghost_str          = "Ghost"; TODO: Add ghost model to hashes
const std::string pumpkinbomb_str    = "Pumpkin Bomb";
const std::string crumpkin_str       = "Crumpkin";
const std::string gargoyle_str       = "Gargoyle";
const std::string explosive_str      = "Explosive";
const std::string arrow_str          = "Arrow";
const std::string otherproj_str      = "Projectile";
const std::string sticky_str         = "Sticky";
const std::string pill_str           = "Pipebomb";
const std::string rocket_str         = "Rocket";

// Function called on draw
static void Draw()
{
    if (!enable)
        return;
    PROF_SECTION(DRAW_ESP_PERFORMANCE)
    ProcessEntityPT();
}

// Function called on create move
static void CreateMove()
{
    // Check usersettings if enabled
    if (!*enable)
        return;
    if (CE_BAD(LOCAL_E))
        return;

    // Update entites every 1/5s
    const bool entity_tick = g_GlobalVars->tickcount % TIME_TO_TICKS(0.20f) == 0;

    ResetEntityStrings(entity_tick); // Clear any strings entities have
    entities_need_repaint.clear();   // Clear data on entities that need redraw
    const bool vischeck_tick = g_GlobalVars->tickcount % TIME_TO_TICKS(0.50f) == 0;
    // If not using any other special esp, we lower the min to the max
    // clients
    if (!buildings && !proj_esp && !item_esp)
    {
        { // Prof section ends when out of scope, these brackets here.
            PROF_SECTION(CM_ESP_EntityLoop)
            for (const auto &ent : entity_cache::player_cache)
            {
                ProcessEntity(ent);
                HitboxUpdate(ent);
                ESPData &ent_dat = data.try_emplace(ent->m_IDX, ESPData{}).first->second;

                if (ent_dat.needs_paint)
                {
                    // Checking this every tick is a waste of nanoseconds
                    if (vischeck_tick && vischeck)
                        ent_dat.transparent = !ent->IsVisible();
                    entities_need_repaint.emplace_back(ent, ent->m_vecOrigin().DistToSqr(g_pLocalPlayer->v_Origin));
                }
            }
        }
    }
    else
    {
        { // Prof section ends when out of scope, these brackets here.
            PROF_SECTION(CM_ESP_EntityLoop)
            // Loop through entities
            for (const auto &ent_index : entity_cache::valid_ents)
            {
                // Get an entity from the loop tick and process it
                if (!ent_index->m_bAlivePlayer())
                    continue;

                bool player = ent_index->m_Type() == ENTITY_PLAYER;

                if (player)
                {
                    ProcessEntity(ent_index);
                    HitboxUpdate(ent_index);
                }
                else if (entity_tick)
                    ProcessEntity(ent_index);

                ESPData &ent_data = data.try_emplace(ent_index->m_IDX, ESPData{}).first->second;
                if (ent_data.needs_paint)
                {
                    // Checking this every tick is a waste of nanoseconds
                    // Get an entity from the loop tick and process iProcessEntityPT nanoseconds
                    if (vischeck_tick && vischeck)
                        ent_data.transparent = !ent_index->IsVisible();
                    entities_need_repaint.emplace_back(ent_index, ent_index->m_vecOrigin().DistToSqr(g_pLocalPlayer->v_Origin));
                }
            }
        }
    }
    // Render closer entities later in order to have their text in the foreground
    std::sort(entities_need_repaint.begin(), entities_need_repaint.end(), [](std::pair<CachedEntity *, float> &a, std::pair<CachedEntity *, float> &b) { return a.second > b.second; });
}

void _FASTCALL Sightlines(CachedEntity *ent, rgba_t &fg)
{
    if (((int) sightlines == 2 || ((int) sightlines == 1 && CE_INT(ent, netvar.iClass) == tf_sniper)) && CE_GOOD(ent) && ent->hitboxes.GetHitbox(0))
    {
        PROF_SECTION(PT_esp_sightlines)

        // Get players angle and head position
        Vector &eye_angles = NET_VECTOR(RAW_ENT(ent), netvar.m_angEyeAngles);
        Vector eye_position;
        eye_position = ent->hitboxes.GetHitbox(0)->center;

        // Main ray tracing area
        float sy         = sinf(DEG2RAD(eye_angles.y)); // yaw
        float cy         = cosf(DEG2RAD(eye_angles.y));
        float sp         = sinf(DEG2RAD(eye_angles.x)); // pitch
        float cp         = cosf(DEG2RAD(eye_angles.x));
        Vector forward_t = Vector(cp * cy, cp * sy, -sp);
        // We don't want the sightlines endpoint to go behind us because the
        // world to screen check will fail, but keep it at most 4096
        Vector forward = forward_t * 4096.0F + eye_position;
        Ray_t ray;
        ray.Init(eye_position, forward);
        trace_t trace;
        g_ITrace->TraceRay(ray, MASK_SOLID, &trace::filter_no_player, &trace);

        // Screen vectors
        Vector scn1, scn2;

        // Status vars
        bool found_scn2 = true;

        // Get end point on screen
        if (!draw::WorldToScreen(trace.endpos, scn2))
        {
            // Set status
            found_scn2 = false;
            // Get the end distance from the trace
            float end_distance = trace.endpos.DistTo(eye_position);

            // Loop and look back until we have a vector on screen
            for (int i = 1; i < 500; ++i)
            {
                // Subtract 40 multiplyed by the tick from the end distance
                // and use that as our length to check
                Vector end_vector = forward_t * (end_distance - (10 * i)) + eye_position;
                if (end_vector.DistTo(eye_position) < 1)
                    break;
                if (draw::WorldToScreen(end_vector, scn2))
                {
                    found_scn2 = true;
                    break;
                }
            }
        }

        if (found_scn2)
        {
            // Set status
            bool found_scn1 = true;

            // If we don't have a vector on screen, attempt to find one
            if (!draw::WorldToScreen(eye_position, scn1))
            {
                // Set status
                found_scn1 = false;

                // Loop and look back until we have a vector on screen
                for (int i = 1; i < 500; ++i)
                {
                    // Multiply starting distance by 15, multiplied by the loop tick
                    Vector start_vector = forward_t * (10 * i) + eye_position;
                    // We don't want it to go too far
                    if (start_vector.DistTo(trace.endpos) < 1)
                        break;
                    // Check if we have a vector on screen, if we do then we set our status
                    if (draw::WorldToScreen(start_vector, scn1))
                    {
                        found_scn1 = true;
                        break;
                    }
                }
            }
            // We have both vectors, draw
            if (found_scn1)
                draw::Line(scn1.x, scn1.y, scn2.x - scn1.x, scn2.y - scn1.y, fg, 0.5f);
        }
    }
}

void _FASTCALL Healthbar(EntityType &type, int &classid, rgba_t &fg, ESPData &ent_data, CachedEntity *ent)
{

    if (type == ENTITY_PLAYER || type == ENTITY_BUILDING)
    {
        // Get collidable from the cache
        if (GetCollide(ent))
        {
            // Pull the cached collide info
            int max_x = ent_data.collide_max.x;
            int max_y = ent_data.collide_max.y;
            int min_x = ent_data.collide_min.x;
            int min_y = ent_data.collide_min.y;

            // Get health values
            int health    = 0;
            int healthmax = 0;
            switch (type)
            {
            case ENTITY_PLAYER:
                health    = g_pPlayerResource->GetHealth(ent);
                healthmax = g_pPlayerResource->GetMaxHealth(ent);
                break;
            case ENTITY_BUILDING:
                health    = CE_INT(ent, netvar.iBuildingHealth);
                healthmax = CE_INT(ent, netvar.iBuildingMaxHealth);
                break;
            }

            // Get Colors
            rgba_t hp     = colors::Transparent(colors::Health(health, healthmax), fg.a);
            rgba_t border = ((classid == RCC_PLAYER) && IsPlayerInvisible(ent)) ? colors::FromRGBA8(160, 160, 160, fg.a * 255.0f) : colors::Transparent(colors::black, fg.a);
            // Get bar width and height
            int hbw = (max_x - min_x - 1) * std::min((float) health / (float) healthmax, 1.0f);
            int hbh = (max_y - min_y - 2) * std::min((float) health / (float) healthmax, 1.0f);

            // Top horizontal health bar
            if (*healthbar == 1)
            {
                draw::RectangleOutlined(min_x, min_y - 6, max_x - min_x + 1, 7, border, 0.5f);
                draw::Rectangle(min_x + hbw, min_y - 5, -hbw, 5, hp);
            }
            // Bottom horizontal health bar
            else if (*healthbar == 2)
            {
                draw::RectangleOutlined(min_x, max_y, max_x - min_x + 1, 7, border, 0.5f);
                draw::Rectangle(min_x + hbw, max_y + 1, -hbw, 5, hp);
            }
            // Vertical health bar
            else if (*healthbar == 3)
            {
                draw::RectangleOutlined(min_x - 7, min_y, 7, max_y - min_y, border, 0.5f);
                draw::Rectangle(min_x - 6, max_y - hbh - 1, 5, hbh, hp);
            }
        }
    }
}

void DrawStrings(EntityType &type, bool &transparent, Vector &draw_point, ESPData &ent_data, CachedEntity *ent)
{
    PROF_SECTION(PT_esp_drawstrings)

    // Create our initial point at the center of the entity
    bool origin_is_zero = true;

    // Only get collidable for players and buildings
    if (type == ENTITY_PLAYER || type == ENTITY_BUILDING)
    {
        // Get collidable from the cache
        if (GetCollide(ent))
        {

            // Origin could change so we set to false
            origin_is_zero = false;

            // Pull the cached collide info
            int max_x = ent_data.collide_max.x;
            int max_y = ent_data.collide_max.y;
            int min_x = ent_data.collide_min.x;
            int min_y = ent_data.collide_min.y;

            // Change the position of the draw point depending on the user settings
            switch ((int) esp_text_position)
            {
            case 0:
            { // TOP RIGHT
                draw_point = Vector(max_x + 2, min_y, 0);
            }
            break;
            case 1:
            { // BOTTOM RIGHT
                draw_point = Vector(max_x + 2, max_y - data.at(ent->m_IDX).string_count * 16, 0);
            }
            break;
            case 2:
            {                          // CENTER
                origin_is_zero = true; // origin is still zero so we set to true
            }
            break;
            case 3:
            { // ABOVE CENTER
                draw_point = Vector((min_x + max_x) / 2.0f, min_y - data.at(ent->m_IDX).string_count * 16, 0);
            }
            break;
            case 4:
            { // BELOW
                draw_point = Vector((min_x + max_x) / 2.0f, max_y, 0);
            }
            break;
            case 5:
            { // ABOVE LEFT
                draw_point = Vector(min_x + 2, min_y - data.at(ent->m_IDX).string_count * 16, 0);
            }
            break;
            case 6:
            { // ABOVE RIGHT
                draw_point = Vector(max_x + 2, min_y - data.at(ent->m_IDX).string_count * 16, 0);
            }
            }
        }
    }

    // Loop through strings
    for (const auto &[string, color_l] : ent_data.strings)
    {
        // Pull string from the entity's cached string array
        // If string has a color assigned to it, apply that otherwise use
        // entities color
        rgba_t color = color_l ? color_l : ent_data.color;
        if (transparent)
            color = colors::Transparent(color); // Apply transparency if needed

        // If the origin is centered, we use one method. if not, the other
        if (!origin_is_zero)
        {
            float draw_pointx_tmp = draw_point.x;
            // Above/Below text should be centered
            if (*esp_text_position == 3 || *esp_text_position == 4)
            {
                float w, h;
                fonts::esp->stringSize(string, &w, &h);
                draw_pointx_tmp -= w / 2.0f;
            }
            draw::String(draw_pointx_tmp, draw_point.y, color, string.c_str(), *fonts::esp);
        }

        // Add to the y due to their being text in that spot
        draw_point.y += /*((int)fonts::font_main->height)*/ 15 - 1;
    }
}

void _FASTCALL BoxEsp(EntityType &type, bool &transparent, rgba_t &fg, CachedEntity *ent)
{
    switch (type)
    {
    case ENTITY_PLAYER:
        if (!fg)
            fg = colors::EntityF(ent);
        if (transparent)
            fg = colors::Transparent(fg);
        if (RAW_ENT(ent)->IsDormant())
        {
            fg.r *= 0.75f;
            fg.g *= 0.75f;
            fg.b *= 0.75f;
        }
        if (!box_3d_player && box_esp)
            DrawBox(ent, fg);
        else if (box_3d_player)
            Draw3DBox(ent, fg);
        break;
    case ENTITY_BUILDING:
        if (ent->m_iTeam() == g_pLocalPlayer->team && !team_buildings)
            break;
        if (!fg)
            fg = colors::EntityF(ent);
        if (transparent)
            fg = colors::Transparent(fg);
        if (RAW_ENT(ent)->IsDormant())
        {
            fg.r *= 0.75f;
            fg.g *= 0.75f;
            fg.b *= 0.75f;
        }
        // Draw exit arrow
        // YawToExit is 0.0f on exit and on newly placed still disabled entrances
        // m_iState is 0 when the TP is disabled
        if (ent->m_iClassID() == CL_CLASS(CObjectTeleporter) && CE_FLOAT(ent, netvar.m_flTeleYawToExit) == 0.0f && CE_INT(ent, netvar.m_iTeleState) > 1)
        {
            float sin_a, cos_a;
            // for some reason vAngRotation yaw differs from exit direction, unsure why
            SinCos(DEG2RAD(CE_VECTOR(ent, netvar.m_angRotation).y - 90.0f), &sin_a, &cos_a);

            // pseudo used to rotate properly
            // screen is passed to filledpolygon
            Vector pseudo[3];
            Vector screen[3];

            // 24 = teleporter width and height
            // 16 = arrow size
            pseudo[0].x = 0.0f; // Undefined behaviour bruh
            pseudo[0].y = 16.0f + 24.0f;
            pseudo[1].x = -16.0f;
            pseudo[1].y = 24.0f;
            pseudo[2].x = 16.0f;
            pseudo[2].y = 24.0f;

            // pass vector, get vector
            // 12 is teleporter height, arrow is 12 HU off the ground
            // sin and cos are already passed in captures
            auto rotateVector = [sin_a = sin_a, cos_a = cos_a](Vector &in) { return Vector(in.x * cos_a - in.y * sin_a, in.x * sin_a + in.y * cos_a, 12.0f); };

            // fail check
            bool visible = true;

            // rotate, add vecorigin AND check worldtoscreen at the same time in single loop
            for (int p = 0; p < 3; p++)
                if (!(visible = draw::WorldToScreen(rotateVector(pseudo[p]) + ent->m_vecOrigin(), screen[p])))
                    break;

            // if visible, pass it and draw the whole thing, ez pz
            if (visible)
                draw::Triangle(screen[0].x, screen[0].y, screen[1].x, screen[1].y, screen[2].x, screen[2].y, fg);
        }
        if (!box_3d_building && box_esp)
            DrawBox(ent, fg);
        else if (box_3d_building)
            Draw3DBox(ent, fg);
        break;
    }
}

void _FASTCALL ShowConditions(CachedEntity *ent)
{
    auto clr = colors::EntityF(ent);
    if (RAW_ENT(ent)->IsDormant())
    {
        clr.r *= 0.5f;
        clr.g *= 0.5f;
        clr.b *= 0.5f;
    }

    if (CE_VALID(ent) && RAW_ENT(ent)->IsDormant())
        AddEntityString(ent, dormant_str, colors::FromRGBA8(255, 0, 0, 255));

    if (IsPlayerInvisible(ent))
    {
        if (HasCondition<TFCond_DeadRingered>(ent))
            AddEntityString(ent, in_ringer_str, colors::white);
        else
            AddEntityString(ent, cloaked_str, colors::white);
    }

    if (CE_BYTE(ent, netvar.m_bFeignDeathReady))
        AddEntityString(ent, ready_ringer_str, colors::white);

    if (HasCondition<TFCond_Disguised>(ent))
        AddEntityString(ent, disguised_str, colors::white);

    if (HasCondition<TFCond_GasCoated>(ent))
        AddEntityString(ent, gassed_str, colors::FromRGBA8(77, 77, 255, 255));

    if (IsPlayerInvulnerable(ent))
        AddEntityString(ent, invulnerable_str, colors::FromRGBA8(77, 77, 255, 255));

    if (HasCondition<TFCond_UberBulletResist>(ent))
        AddEntityString(ent, bullet_a_str, colors::FromRGBA8(223, 115, 255, 255));
    else if (HasCondition<TFCond_SmallBulletResist>(ent))
        AddEntityString(ent, bullet_p_str, colors::FromRGBA8(223, 115, 255, 255));

    if (HasCondition<TFCond_UberFireResist>(ent))
        AddEntityString(ent, fire_a_str, colors::FromRGBA8(223, 115, 255, 255));
    else if (HasCondition<TFCond_SmallFireResist>(ent))
        AddEntityString(ent, fire_p_str, colors::FromRGBA8(223, 115, 255, 255));

    if (HasCondition<TFCond_UberBlastResist>(ent))
        AddEntityString(ent, blast_a_str, colors::FromRGBA8(223, 115, 255, 255));
    else if (HasCondition<TFCond_SmallBlastResist>(ent))
        AddEntityString(ent, blast_p_str, colors::FromRGBA8(223, 115, 255, 255));

    if (IsPlayerCritBoosted(ent))
        AddEntityString(ent, crit_str, colors::orange);

    auto weapon_idx      = HandleToIDX(CE_INT(ent, netvar.hActiveWeapon));
    CachedEntity *weapon = IDX_GOOD(weapon_idx) ? ENTITY(weapon_idx) : nullptr;

    if (CE_GOOD(weapon) && weapon->m_iClassID() == CL_CLASS(CTFMinigun) && CE_INT(weapon, netvar.iWeaponState) != 0)
        AddEntityString(ent, revving_str, colors::FromRGBA8(255, 215, 0, 255));
    else if (CE_GOOD(weapon) && weapon->m_iClassID() == CL_CLASS(CTFCompoundBow) && HasCondition<TFCond_Slowed>(ent))
        AddEntityString(ent, drawn_str, colors::FromRGBA8(255, 215, 0, 255));
    else if (HasCondition<TFCond_Zoomed>(ent))
        AddEntityString(ent, zooming_str, colors::FromRGBA8(220, 220, 220, 255));
    else if (HasCondition<TFCond_Slowed>(ent))
        AddEntityString(ent, slowed_str, colors::FromRGBA8(220, 220, 220, 255));

    if (HasCondition<TFCond_Jarated>(ent))
        AddEntityString(ent, jarated_str, colors::white);

    if (HasCondition<TFCond_Milked>(ent))
        AddEntityString(ent, milked_str, colors::white);

    if (HasCondition<TFCond_OnFire>(ent))
        AddEntityString(ent, burn_str, colors::FromRGBA8(255, 0, 0, 255));

    if (HasCondition<TFCond_Bleeding>(ent) || HasCondition<TFCond_GrapplingHookBleeding>(ent))
        AddEntityString(ent, bleed_str, colors::FromRGBA8(255, 0, 0, 255));

    if (HasCondition<TFCond_Taunting>(ent))
        AddEntityString(ent, taunting_str, colors::FromRGBA8(191, 0, 255, 255));
}

// Used when processing entities with cached data from createmove in draw
void ProcessEntityPT()
{
    PROF_SECTION(PT_esp_process_entity)
    for (const auto &[ent, distance] : entities_need_repaint)
    {
        // Check to prevent crashes
        if (CE_INVALID(ent) || !ent->m_bAlivePlayer())
            continue;
        // Dormant
        bool dormant = false;
        if (RAW_ENT(ent)->IsDormant())
        {
            if (!ent->m_vecDormantOrigin())
                continue;
            dormant = true;
        }

        int classid     = ent->m_iClassID();
        EntityType type = ent->m_Type();
        // Grab esp data
        ESPData &ent_data = data[ent->m_IDX];

        // Get color of entity
        // TODO, check if we can move this after world to screen check
        rgba_t fg = ent_data.color;
        if (!fg || fg.a == 0.0f)
        {
            fg = colors::EntityF(ent);
            if (dormant)
            {
                fg.r *= 0.75f;
                fg.g *= 0.75f;
                fg.b *= 0.75f;
            }
            ent_data.color = fg;
        }

        // Check if entity is on screen, then save screen position if true
        auto position = ent->m_vecDormantOrigin();
        if (!position)
            continue;

        // Sightline esp
        if (sightlines && type == ENTITY_PLAYER)
            Sightlines(ent, fg);

        static Vector screen;
        if (!draw::EntityCenterToScreen(ent, screen))
            continue;

        // Reset the collide cache
        ent_data.has_collide = false;

        // Get if ent should be transparent
        bool transparent = vischeck && ent_data.transparent;

        // Box esp
        if (box_esp || box_3d_player || box_3d_building)
            BoxEsp(type, transparent, fg, ent);

        if (draw_bones)
        {
            if (vischeck && !ent->IsVisible())
                transparent = true;
            rgba_t bone_color = colors::EntityF(ent);
            if (transparent)
                bone_color = colors::Transparent(bone_color);

            static bonelist_s bl;
            bl.success = false;
            bl.setup   = false;
            if (!CE_INVALID(ent) && ent->m_bAlivePlayer() && !RAW_ENT(ent)->IsDormant())
            {
                if (bones_color)
                    bl.Draw(ent, bone_color);
                else
                    bl.Draw(ent, colors::white);
            }
        }

        // Health bar
        if (*healthbar != 0)
            Healthbar(type, classid, fg, ent_data, ent);
        // We only want health bars on players and buildings

        // Check if entity has strings to draw
        if (ent_data.string_count)
            DrawStrings(type, transparent, screen, ent_data, ent);
    }
}

static std::string write_str;
// Used to process entities from CreateMove
void _FASTCALL ProcessEntity(CachedEntity *ent)
{
    auto origin = ent->m_vecDormantOrigin();
    // Dormant and no data
    if (!origin)
        return;

    {
        // We don't actually care about this vector at all. It just exists so WorldToScreen can function normally
        static Vector origin_screen;
        if (!sightlines && ent->m_Type() != ENTITY_PLAYER && !draw::WorldToScreen(*origin, origin_screen))
            return;
    }

    auto distance = ent->m_flDistance();

    if (max_dist && distance > *max_dist)
        return;
    int classid = ent->m_iClassID();
    // Entity esp
    if (entity_info)
    {
        AddEntityString(ent, format(RAW_ENT(ent)->GetClientClass()->m_pNetworkName, " [", classid, "]"));
        if (entity_id)
            AddEntityString(ent, std::to_string(ent->m_IDX));

        if (entity_model)
        {
            const model_t *model = RAW_ENT(ent)->GetModel();
            if (model)
                AddEntityString(ent, std::string(g_IModelInfo->GetModelName(model)));
        }
    }

    // Get esp data from current ent
    ESPData &espdata = data[ent->m_IDX];

    switch (ent->m_Type())
    {
    case ENTITY_PROJECTILE:
    {
        if (proj_esp && (ent->m_bEnemy() || (teammates && !proj_enemy)))
        {
            switch (classid)
            {
            case CL_CLASS(CTFProjectile_Rocket):
            case CL_CLASS(CTFProjectile_SentryRocket): // Rockets
                AddEntityString(ent, rocket_str);
                break;
            case CL_CLASS(CTFGrenadePipebombProjectile): // Pills/Stickys
            {
                switch (CE_INT(ent, netvar.iPipeType)) // Switch based on pills/stickys
                {
                case 0: // Pills
                    AddEntityString(ent, pill_str);
                    break;
                case 1: // Stickys
                    AddEntityString(ent, sticky_str);
                    break;
                }
                break;
            }
            case CL_CLASS(CTFProjectile_Jar):
            case CL_CLASS(CTFProjectile_JarGas):
            case CL_CLASS(CTFProjectile_JarMilk):
            case CL_CLASS(CTFProjectile_Flare):
            case CL_CLASS(CTFProjectile_Cleaver):
            case CL_CLASS(CTFProjectile_ThrowableBreadMonster):
            case CL_CLASS(CTFProjectile_EnergyRing):
            case CL_CLASS(CTFProjectile_EnergyBall):
            case CL_CLASS(CTFProjectile_GrapplingHook):
            case CL_CLASS(CTFProjectile_BallOfFire):
            {
                if (CE_VECTOR(ent, netvar.vVelocity).IsZero()) // Ignore non-moving projectiles
                    break;
                AddEntityString(ent, otherproj_str);
                break;
            }
            case CL_CLASS(CTFProjectile_Arrow):       // Huntsman
            case CL_CLASS(CTFProjectile_HealingBolt): // Crusader's Crossbow
            {
                if (CE_VECTOR(ent, netvar.vVelocity).IsZero()) // Ignore non-moving projectiles
                    break;
                AddEntityString(ent, arrow_str);
                break;
            }
            }
        }
        break;
    }
    case ENTITY_PLAYER:
    {
        if (ent->m_bAlivePlayer())
        {
            // Local player handling
            if (!(local_esp && g_IInput->CAM_IsThirdPerson()) && ent->m_IDX == g_IEngine->GetLocalPlayer())
                return;
            if (hide_invis && IsPlayerInvisible(ent))
                return;

            // Get player class
            int pclass = CE_INT(ent, netvar.iClass);

            // Attempt to get player info, and if cant, return
            player_info_s info{};
            if (!GetPlayerInfo(ent->m_IDX, &info))
                return;

            // Legit mode handling
            if (legit && ent->m_bEnemy() && playerlist::IsDefault(info.friendsID))
            {
                if (IsPlayerInvisible(ent))
                    return; // Invis check
                if (vischeck && !ent->IsVisible())
                    return;
            }

            // Powerup handling
            if (powerup_esp)
            {
                powerup_type power = GetPowerupOnPlayer(ent);
                if (power != not_powerup)
                    AddEntityString(ent, std::string("^ ") + powerups[power] + " ^");
            }

            if (ent->m_bEnemy() || teammates || player_tools::shouldAlwaysRenderEsp(ent))
            {
                // Playername
                if (show_name)
                    AddEntityString(ent, std::string(info.name));

                // Player class
                if (show_class && pclass > 0 && pclass < 10)
                    AddEntityString(ent, classes[pclass - 1]);

                // Health esp
                if (show_health)
                {
                    int health     = g_pPlayerResource->GetHealth(ent);
                    int max_health = g_pPlayerResource->GetMaxHealth(ent);
                    AddEntityString(ent, format(health), colors::Health(health, max_health));
                }
                // Medigun Ubercharge esp
                if (show_ubercharge)
                {
                    if (CE_INT(ent, netvar.iClass) == tf_medic)
                    {
                        int *hWeapons = &CE_INT(ent, netvar.hMyWeapons);
                        for (int i = 0; hWeapons[i]; ++i)
                        {
                            if (IDX_BAD(HandleToIDX(hWeapons[i])))
                                continue;
                            CachedEntity *weapon = ENTITY(HandleToIDX(hWeapons[i]));
                            if (CE_VALID(weapon) && weapon->m_iClassID() == CL_CLASS(CWeaponMedigun))
                            {
                                std::string charge = std::to_string(int(CE_FLOAT(weapon, netvar.m_flChargeLevel) * 100));

                                if (CE_INT(weapon, netvar.iItemDefinitionIndex) != 998)
                                    AddEntityString(ent, charge + "%", colors::Health(CE_FLOAT(weapon, netvar.m_flChargeLevel) * 100, 100));
                                else
                                    AddEntityString(ent, charge + "% | " + std::to_string(int(CE_FLOAT(weapon, netvar.m_flChargeLevel) / 0.25f)), colors::Health((CE_FLOAT(weapon, netvar.m_flChargeLevel) * 100), 100));
                                break;
                            }
                        }
                    }
                }
                // Conditions esp
                if (show_conditions)
                    ShowConditions(ent);

                // Active weapon esp
                if (show_weapon)
                {
                    int widx = HandleToIDX(CE_INT(ent, netvar.hActiveWeapon));
                    if (IDX_GOOD(widx))
                    {
                        CachedEntity *weapon = ENTITY(widx);
                        if (CE_VALID(weapon) && re::C_BaseCombatWeapon::IsBaseCombatWeapon(RAW_ENT(weapon)))
                        {
                            const char *weapon_name = g_ILocalize->FindAsUTF8(re::C_BaseCombatWeapon::GetPrintName(RAW_ENT(weapon)));
                            if (weapon_name)
                                AddEntityString(ent, std::string(weapon_name));
                        }
                    }
                }

                // Notify esp to repaint
                RepaintEnt(ent, distance);
            }
        }
        break;
    }
    case ENTITY_NPC:
    {
        if (npc && ent->m_Type() == ENTITY_NPC)
        {
            switch (classid)
            {
            case CL_CLASS(CTFTankBoss):
                write_str = tank_str;
                break;
            case CL_CLASS(CMerasmus):
            case CL_CLASS(CMerasmusDancer):
                write_str = merasmus_str;
                break;
            case CL_CLASS(CZombie):
                write_str = skeleton_str;
                break;
            case CL_CLASS(CEyeballBoss):
                write_str = monoculus_str;
                break;
            case CL_CLASS(CHeadlessHatman):
                write_str = horsemann_str;
                break;
            }
            AddEntityString(ent, write_str, colors::FromRGBA8(236, 14, 217, 255));
        }
        break;
    }
    case ENTITY_BUILDING:
    {
        if (buildings)
        {
            // Check if enemy building
            if (!team_buildings && !ent->m_bEnemy())
                return;

            bool IsMini = CE_BYTE(ent, netvar.m_bMiniBuilding);

            // Make a name for the building based on the building type and level
            if (show_name || show_class)
            {
                const std::string &name = (classid == CL_CLASS(CObjectTeleporter) && CE_FLOAT(ent, netvar.m_flTeleYawToExit) == 0.0f && CE_INT(ent, netvar.m_iTeleState) > 1) ? teleporterexit_str : (classid == CL_CLASS(CObjectTeleporter) ? teleporter_str : (classid == CL_CLASS(CObjectSentrygun) ? sentry_str : dispenser_str));

                if (!IsMini)
                {
                    int level = CE_INT(ent, netvar.iUpgradeLevel);
                    AddEntityString(ent, format(name), colors::white);
                    AddEntityString(ent, format("LEVEL ", level));
                }
                else
                    AddEntityString(ent, std::string("Mini ") + name, colors::white);
            }

            // If text health is true, then add a string with the health
            if (show_health)
                AddEntityString(ent, format(ent->m_iHealth()), colors::Health(ent->m_iHealth(), ent->m_iMaxHealth()));

            if (show_conditions)
            {
                switch (classid)
                {
                case CL_CLASS(CObjectSentrygun):
                {
                    bool IsControlled  = CE_BYTE(ent, netvar.m_bPlayerControlled);
                    int sentry_ammo    = CE_INT(ent, netvar.m_iAmmoShells);
                    int sentry_rockets = CE_INT(ent, netvar.m_iAmmoRockets);

                    AddEntityString(ent, format(std::to_string(sentry_ammo)));

                    if (CE_INT(ent, netvar.iUpgradeLevel) == 3)
                        AddEntityString(ent, format(std::to_string(sentry_rockets)));

                    if (IsControlled) // Dispensers are also "controlled" when they're in use
                        AddEntityString(ent, controlled_str, colors::FromRGBA8(220.0f, 220.0f, 220.0f, 255.0f));
                    break;
                }
                case CL_CLASS(CObjectDispenser):
                {
                    int AmmoMetal = CE_INT(ent, netvar.m_iAmmoMetal);

                    AddEntityString(ent, format(std::to_string(AmmoMetal)));
                    break;
                }
                case CL_CLASS(CObjectTeleporter):
                {
                    if (CE_INT(ent, netvar.m_iTeleState) > 1)
                    {
                        float next_teleport = CE_FLOAT(ent, netvar.m_flTeleRechargeTime);
                        float yaw_to_exit   = CE_FLOAT(ent, netvar.m_flTeleYawToExit);
                        std::string time    = std::to_string(int(SERVER_TIME - next_teleport));
                        time.append("s");

                        if (yaw_to_exit)
                        {
                            if (SERVER_TIME > next_teleport)
                                AddEntityString(ent, tp_ready_str);
                            else
                                AddEntityString(ent, time);
                        }
                    }
                    break;
                }
                }

                bool IsSapped         = CE_BYTE(ent, netvar.m_bHasSapper);
                bool IsDisabled       = CE_BYTE(ent, netvar.m_bDisabled);
                bool IsPlasmaDisabled = CE_BYTE(ent, netvar.m_bPlasmaDisable);

                if (IsSapped)
                    AddEntityString(ent, sapped_str, colors::FromRGBA8(220.0f, 220.0f, 220.0f, 255.0f));

                else if ((classid == CL_CLASS(CObjectTeleporter) && CE_INT(ent, netvar.m_iTeleState) <= 1) || IsDisabled || IsPlasmaDisabled)
                    AddEntityString(ent, disabled_str, colors::FromRGBA8(220.0f, 220.0f, 220.0f, 255.0f));
            }

            // Set the entity to repaint
            RepaintEnt(ent, distance);
        }
        break;
    }
    default:
        if (item_esp)
        {
            const model_t *model = RAW_ENT(ent)->GetModel();
            if (model)
            {
                const auto szName = g_IModelInfo->GetModelName(model);
                // Gargoyle esp
                if (item_gargoyle && classid == CL_CLASS(CHalloweenGiftPickup))
                {
                    if (HandleToIDX(CE_INT(ent, netvar.m_hTargetPlayer)) == g_pLocalPlayer->entity_idx)
                        AddEntityString(ent, gargoyle_str, colors::FromRGBA8(199, 21, 133, 255));
                    return;
                }
                // Explosive/Environmental hazard esp
                else if (item_explosive && (classid == CL_CLASS(CTFPumpkinBomb) || Hash::IsHazard(szName)))
                {
                    if (classid == CL_CLASS(CTFPumpkinBomb))
                        AddEntityString(ent, pumpkinbomb_str, colors::FromRGBA8(255, 162, 0, 255));
                    else
                        AddEntityString(ent, explosive_str, colors::FromRGBA8(255, 162, 0, 255));
                    return;
                }
                if (item_objectives && (classid == CL_CLASS(CCaptureFlag) || (Hash::IsFlag(szName) || Hash::IsBombCart(szName) || Hash::IsBombCartRed(szName))))
                {
                    rgba_t color = ent->m_iTeam() == TEAM_BLU ? colors::blu : (ent->m_iTeam() == TEAM_RED ? colors::red : colors::white);

                    if (Hash::IsFlag(szName))
                        AddEntityString(ent, objective_str, color);
                    else if (Hash::IsBombCartRed(szName))
                        AddEntityString(ent, objective_str, colors::red);
                    else if (Hash::IsBombCart(szName))
                        AddEntityString(ent, objective_str, colors::blu);

                    auto resettime   = CE_FLOAT(ent, netvar.m_flResetTime);
                    std::string time = std::to_string(int(resettime - SERVER_TIME));
                    time.append("s");

                    if (resettime && classid == CL_CLASS(CCaptureFlag))
                        AddEntityString(ent, time, colors::white);
                    return;
                }
                // Health pack esp
                if (item_health_packs && Hash::IsHealth(szName))
                    AddEntityString(ent, healthpack_str);
                // Ammo esp
                else if (item_ammo_packs && Hash::IsAmmo(szName))
                    AddEntityString(ent, ammopack_str);
                // Powerup esp
                // else if (item_powerups && (Hash::IsPowerup(szName)))
                // AddEntityString(ent, powerups[itemtype - ITEM_POWERUP_FIRST]);
                // Halloween spell esp
                else if (item_spellbooks && (Hash::IsSpellbook(szName) || Hash::IsSpellbookRare(szName)))
                {
                    if (Hash::IsSpellbookRare(szName))
                        AddEntityString(ent, rare_spell_str, colors::FromRGBA8(139, 31, 221, 255));
                    else
                        AddEntityString(ent, spell_str, colors::green);
                }
                // Crumpkin esp https://wiki.teamfortress.com/wiki/Halloween_pumpkin
                else if (item_crumpkin && Hash::IsCrumpkin(szName))
                    AddEntityString(ent, crumpkin_str, colors::FromRGBA8(253, 203, 88, 255));
            }
            // MVM Money esp
            if (item_money && classid == CL_CLASS(CCurrencyPack) && !CE_BYTE(ent, netvar.bDistributed))
                AddEntityString(ent, mvm_money_str);
        }
    }
}

// Draw 3D box around player/building
void _FASTCALL Draw3DBox(CachedEntity *ent, const rgba_t &clr)
{
    if (CE_INVALID(ent) || !ent->m_bAlivePlayer())
        return;

    Vector origin = RAW_ENT(ent)->GetCollideable()->GetCollisionOrigin();
    Vector mins   = RAW_ENT(ent)->GetCollideable()->OBBMins();
    Vector maxs   = RAW_ENT(ent)->GetCollideable()->OBBMaxs();
    // Dormant
    if (RAW_ENT(ent)->IsDormant())
        origin = *ent->m_vecDormantOrigin();

    // Create an array for storing box points
    Vector corners[8]; // World vectors
    Vector points[8];  // Screen vectors

    // Create points for the box based on max and mins
    float x    = maxs.x - mins.x;
    float y    = maxs.y - mins.y;
    float z    = maxs.z - mins.z;
    corners[0] = mins;
    corners[1] = mins + Vector(x, 0, 0);
    corners[2] = mins + Vector(x, y, 0);
    corners[3] = mins + Vector(0, y, 0);
    corners[4] = mins + Vector(0, 0, z);
    corners[5] = mins + Vector(x, 0, z);
    corners[6] = mins + Vector(x, y, z);
    corners[7] = mins + Vector(0, y, z);

    // Rotate the box and check if any point of the box isn't on the screen
    for (unsigned i = 0; i < 8; ++i)
    {
        float yaw    = NET_VECTOR(RAW_ENT(ent), netvar.m_angEyeAngles).y;
        float s      = sinf(DEG2RAD(yaw));
        float c      = cosf(DEG2RAD(yaw));
        float xx     = corners[i].x;
        float yy     = corners[i].y;
        corners[i].x = (xx * c) - (yy * s);
        corners[i].y = (xx * s) + (yy * c);
        corners[i] += origin;

        if (!draw::WorldToScreen(corners[i], points[i]))
            return;
    }
    rgba_t draw_clr = clr;
    // Draw the actual box
    for (unsigned i = 1; i <= 4; ++i)
    {
        draw::Line((points[i - 1].x), (points[i - 1].y), (points[i % 4].x) - (points[i - 1].x), (points[i % 4].y) - (points[i - 1].y), draw_clr, 0.5f);
        draw::Line((points[i - 1].x), (points[i - 1].y), (points[i + 3].x) - (points[i - 1].x), (points[i + 3].y) - (points[i - 1].y), draw_clr, 0.5f);
        draw::Line((points[i + 3].x), (points[i + 3].y), (points[i % 4 + 4].x) - (points[i + 3].x), (points[i % 4 + 4].y) - (points[i + 3].y), draw_clr, 0.5f);
    }
}

void Shutdown()
{
    data.clear();
}

// Draw a box around a player
void _FASTCALL DrawBox(CachedEntity *ent, const rgba_t &clr)
{
    PROF_SECTION(PT_esp_drawbox)

    // Check if ent is bad to prevent crashes
    if (CE_INVALID(ent) || !ent->m_bAlivePlayer())
        return;

    // Get our collidable bounds
    if (!GetCollide(ent))
        return;

    // Pull the cached collide info
    ESPData &ent_data = data[ent->m_IDX];
    int max_x         = ent_data.collide_max.x;
    int max_y         = ent_data.collide_max.y;
    int min_x         = ent_data.collide_min.x;
    int min_y         = ent_data.collide_min.y;

    // Depending on whether the player is cloaked, we change the color accordingly
    rgba_t border = ((ent->m_iClassID() == RCC_PLAYER) && IsPlayerInvisible(ent)) ? colors::FromRGBA8(192, 192, 192, clr.a * 255.0f) : colors::Transparent(colors::black, clr.a);
    // With box corners, we draw differently
    if ((int) box_esp == 2)
        BoxCorners(min_x, min_y, max_x, max_y, clr, (clr.a != 1.0f));
    // Otherwise, we just do simple draw funcs
    else
    {
        draw::RectangleOutlined(min_x, min_y, max_x - min_x, max_y - min_y, border, 0.5f);
        draw::RectangleOutlined(min_x + 1, min_y + 1, max_x - min_x - 2, max_y - min_y - 2, clr, 0.5f);
        draw::RectangleOutlined(min_x + 2, min_y + 2, max_x - min_x - 4, max_y - min_y - 4, border, 0.5f);
    }
}

// Function to draw box corners, Used by DrawBox
void BoxCorners(int minx, int miny, int maxx, int maxy, const rgba_t &color, bool transparent)
{
    const rgba_t &black    = transparent ? colors::Transparent(colors::black) : colors::black;
    const float heightSize = ((float) *box_corner_size_height / 100) * (maxy - miny - 3);
    const float widthSize  = ((float) *box_corner_size_width / 100) * (maxx - minx - 2);

    // Black corners
    // Top Left
    draw::Rectangle(minx, miny, widthSize + 1, 3, black);
    draw::Rectangle(minx, miny + 3, 3, heightSize - 3, black);
    // Top Right
    draw::Rectangle(maxx, miny, -widthSize - 1, 3, black);
    draw::Rectangle(maxx - 3 + 1, miny + 3, 3, heightSize - 3, black);
    // Bottom Left
    draw::Rectangle(minx, maxy - 3, widthSize + 1, 3, black);
    draw::Rectangle(minx, maxy, 3, -heightSize - 3, black);
    // Bottom Right
    draw::Rectangle(maxx, maxy - 3, -widthSize - 1, 3, black);
    draw::Rectangle(maxx - 2, maxy, 3, -heightSize - 3, black);

    // Colored corners
    // Top Left
    draw::Line(minx + 1, miny + 1, widthSize, 0, color, 0.5f);
    draw::Line(minx + 1, miny + 1, 0, heightSize, color, 0.5f);
    // Top Right
    draw::Line(maxx - 1, miny + 1, -widthSize, 0, color, 0.5f);
    draw::Line(maxx - 1, miny + 1, 0, heightSize, color, 0.5f);
    // Bottom Left
    draw::Line(minx + 1, maxy - 2, widthSize, 0, color, 0.5f);
    draw::Line(minx + 1, maxy - 2, 0, -heightSize, color, 0.5f);
    // Bottom Right
    draw::Line(maxx - 1, maxy - 2, -widthSize, 0, color, 0.5f);
    draw::Line(maxx - 1, maxy - 2, 0, -heightSize, color, 0.5f);
}

// Used for caching collidable bounds
bool GetCollide(CachedEntity *ent)
{
    PROF_SECTION(PT_esp_getcollide)

    // Null check to prevent crashing
    if (CE_INVALID(ent) || !ent->m_bAlivePlayer())
        return false;

    // Grab esp data
    ESPData &ent_data = data[ent->m_IDX];

    // If entity has cached collides, return it. Otherwise, generate new bounds
    if (!ent_data.has_collide)
    {

        // Get collision center, max, and mins
        Vector origin = RAW_ENT(ent)->GetCollideable()->GetCollisionOrigin();
        // Dormant
        if (RAW_ENT(ent)->IsDormant())
        {
            auto vec = ent->m_vecDormantOrigin();
            if (!vec)
                return false;
            origin = *vec;
        }
        Vector mins = RAW_ENT(ent)->GetCollideable()->OBBMins() + origin;
        Vector maxs = RAW_ENT(ent)->GetCollideable()->OBBMaxs() + origin;

        // Create an array for storing box points
        Vector points_r[8]; // World vectors
        Vector points[8];   // Screen vectors

        // If user setting for box expand is true, spread the max and mins
        if (esp_expand)
        {
            const float exp = *esp_expand;
            maxs.x += exp;
            maxs.y += exp;
            maxs.z += exp;
            mins.x -= exp;
            mins.y -= exp;
            mins.z -= exp;
        }

        // Create points for the box based on max and mins
        float x     = maxs.x - mins.x;
        float y     = maxs.y - mins.y;
        float z     = maxs.z - mins.z;
        points_r[0] = mins;
        points_r[1] = mins + Vector(x, 0, 0);
        points_r[2] = mins + Vector(x, y, 0);
        points_r[3] = mins + Vector(0, y, 0);
        points_r[4] = mins + Vector(0, 0, z);
        points_r[5] = mins + Vector(x, 0, z);
        points_r[6] = mins + Vector(x, y, z);
        points_r[7] = mins + Vector(0, y, z);

        // Check if any point of the box isn't on the screen
        for (unsigned i = 0; i < 8; ++i)
            if (!draw::WorldToScreen(points_r[i], points[i]))
                return false;

        // Get max and min of the box using the newly created screen vector
        int max_x = -1;
        int max_y = -1;
        int min_x = 65536;
        int min_y = 65536;
        for (auto &point : points)
        {
            if (point.x > max_x)
                max_x = point.x;
            if (point.y > max_y)
                max_y = point.y;
            if (point.x < min_x)
                min_x = point.x;
            if (point.y < min_y)
                min_y = point.y;
        }

        // Save the info to the esp data and notify cached that we cached info.
        ent_data.collide_max = Vector(max_x, max_y, 0);
        ent_data.collide_min = Vector(min_x, min_y, 0);
        ent_data.has_collide = true;

        return true;
    }
    else
        // We already have collidable so return true.
        return true;
}

// Function to reset entity's strings
void ResetEntityStrings(bool full_clear)
{
    if (full_clear)
    {
        for (auto &[key, val] : data)
        {
            val.string_count = 0;
            val.color        = colors::empty;
            val.needs_paint  = false;
            val.strings.clear();
        }
    }
    else
    {
        for (u_int16_t i = 1; i < g_GlobalVars->maxClients; ++i)
        {
            auto &element        = data[i];
            element.string_count = 0;
            element.color        = colors::empty;
            element.needs_paint  = false;
            element.strings.clear();
        }
    }
}

static InitRoutine init(
    []()
    {
        EC::Register(EC::CreateMove, CreateMove, "CM_ESP", EC::average);
#if ENABLE_VISUALS
        EC::Register(EC::Draw, Draw, "DRAW_ESP", EC::average);
#endif
    });

} // namespace hacks::esp
