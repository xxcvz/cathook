/*
 * HAimbot.cpp
 *
 *  Created on: Oct 9, 2016
 *      Author: nullifiedcat
 */

#include "HAimbot.h"

#include "../usercmd.h"
#include "../helpers.h"
#include "../entity.h"
#include "../interfaces.h"
#include "../trace.h"
#include "../targethelper.h"
#include "../localplayer.h"
#include "../drawing.h"

//typedef int CBaseEntity;

#include "../fixsdk.h"
#include <client_class.h>
#include <inetchannelinfo.h>
#include <icliententity.h>
#include <icliententitylist.h>
#include <cdll_int.h>
#include <gametrace.h>
#include <engine/IEngineTrace.h>
#include "../sdk/in_buttons.h"

Vector viewangles_old;
bool fix_silent;

int target_lock;

/* null-safe */
void HAimbot::Create() {
	this->v_bEnabled = CreateConVar("u_aimbot_enabled", "0", "Enables aimbot. EXPERIMENTAL AND TOTALLY NOT LEGIT");
	this->v_iHitbox = CreateConVar("u_aimbot_hitbox", "0", "Hitbox");
	this->v_bAutoHitbox = CreateConVar("u_aimbot_autohitbox", "1", "Autohitbox");
	this->v_bPrediction = CreateConVar("u_aimbot_prediction", "1", "Latency prediction");
	this->v_bAutoShoot = CreateConVar("u_aimbot_autoshoot", "1", "Autoshoot");
	this->v_bSilent = CreateConVar("u_aimbot_silent", "1", "Silent mode");
	this->v_bZoomedOnly = CreateConVar("u_aimbot_zoomed", "1", "Only acitve with zoomed rifle");
	this->v_iAutoShootCharge = CreateConVar("u_aimbot_autoshoot_charge", "0.0", "Minimal charge for autoshoot");
	this->v_iMinRange = CreateConVar("u_aimbot_minrange", "0", "Minimum range to aim");
	this->v_bPriority = CreateConVar("u_aimbot_priority", "1", "Use priority system");
	this->v_bRespectCloak = CreateConVar("u_aimbot_respect_cloak", "1", "Will not shoot cloaked spies.");
	this->v_bCharge = CreateConVar("u_aimbot_charge", "0", "Autoshoot only with charge ready");
	this->v_bEnabledAttacking = CreateConVar("u_aimbot_enable_attack_only", "0", "Aimbot only active with attack key held");
	this->v_bStrictAttack = CreateConVar("u_aimbot_strict_attack", "0", "Not attacking unless target is locked");
	this->v_bProjectileAimbot = CreateConVar("u_aimbot_projectile", "1", "Projectile aimbot (EXPERIMENTAL)");
	this->v_iOverrideProjSpeed = CreateConVar("u_aimbot_proj_speed", "0", "Override proj speed");
	this->v_bDebug = CreateConVar("u_aimbot_debug", "0", "Aimbot debug");
	this->v_iFOV = CreateConVar("u_aimbot_fov", "0", "FOV aimbot (experimental)");
	this->v_bMachinaPenetration = CreateConVar("u_aimbot_machina", "0", "Machina penetration aimbot (just for fun)");
	fix_silent = false;
}

bool HAimbot::CreateMove(void*, float, CUserCmd* cmd) {
	if (!this->v_bEnabled->GetBool()) return true;
	this->m_iLastTarget = -1;
	if (this->v_bEnabledAttacking->GetBool() && !(cmd->buttons & IN_ATTACK)) {
		return true;
	}

	if (g_pLocalPlayer->weapon && g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == ClassID::CTFMinigun) {
		if (!(g_pLocalPlayer->cond_0 & cond::slowed)) {
			return true;
		}
		if (!(cmd->buttons & IN_ATTACK2)) {
			return true;
		}
	}

	if (g_pLocalPlayer->bIsReloading) {
		return true;
	}

	if (this->v_bStrictAttack->GetBool() ) {
		cmd->buttons = cmd->buttons &~ IN_ATTACK;
	}
	IClientEntity* player = g_pLocalPlayer->entity;
	if (!player) return true;
	if (player->IsDormant()) return true;
	m_iHitbox = this->v_iHitbox->GetInt();
	if (this->v_bAutoHitbox->GetBool()) m_iHitbox = 7;
	if (g_pLocalPlayer->weapon) {
		if (g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == ClassID::CTFSniperRifle ||
			g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == ClassID::CTFSniperRifleDecap) {
			if (!CanHeadshot(g_pLocalPlayer->entity)) {
				if (this->v_bZoomedOnly->GetBool()) return true;
			} else {
				if (this->v_bAutoHitbox->GetBool()) m_iHitbox = 0;
			}
		}
	}

	if (this->v_bZoomedOnly->GetBool()) {
		// TODO IsSniperRifle()
		if (g_pLocalPlayer->weapon) {
			if (g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == ClassID::CTFSniperRifle ||
				g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == ClassID::CTFSniperRifleDecap) {
				if (!CanHeadshot(g_pLocalPlayer->entity)) return true;
			}
		}
	}
	if (g_pLocalPlayer->weapon) {
		if (g_pLocalPlayer->weapon->GetClientClass()->m_ClassID == 210) return true;
	}

	m_bProjectileMode = (GetProjectileData(g_pLocalPlayer->weapon, m_flProjSpeed, m_bProjArc));
	// TODO priority modes (FOV, Smart, Distance, etc)
	if (!this->v_bPriority->GetBool()) {
		IClientEntity* target_locked = interfaces::entityList->GetClientEntity(target_lock);
		if (target_locked != 0) {
			if (ShouldTarget(target_locked)) {
				Aim(target_locked, cmd);
				return true;
			} else {
				target_lock = 0;
			}
		}
	}
	IClientEntity* target_highest = 0;
	int target_highest_score = -256;
	for (int i = 0; i < interfaces::entityList->GetHighestEntityIndex(); i++) {
		IClientEntity* ent = interfaces::entityList->GetClientEntity(i);
		if (ent == 0) continue;
		if (!(IsPlayer(ent) || IsBuilding(ent))) continue;
		if (ShouldTarget(ent)) {
			//if (v_bDebug->GetBool()) {

			//}
			if (!this->v_bPriority->GetBool()) {
				target_lock = i;
				this->m_iLastTarget = target_lock;
				if (Aim(ent, cmd)) {
					continue;
				}
			} else {
				int scr = GetScoreForEntity(ent);
				if (scr > target_highest_score) {
					target_highest_score = scr;
					target_highest = ent;
				}
			}
		}
	}
	if (this->v_bPriority->GetBool()) {
		if (target_highest != 0) {
			this->m_iLastTarget = target_highest->entindex();
			Aim(target_highest, cmd);
		}
	}
	return !this->v_bSilent->GetBool();
}

void HAimbot::Destroy() {}
void HAimbot::PaintTraverse(void*, unsigned int, bool, bool) {
	if (!v_bEnabled->GetBool()) return;
	if (this->m_iLastTarget == -1) return;
	IClientEntity* ent = interfaces::entityList->GetClientEntity(this->m_iLastTarget);
	if (!ent) return;
	if (IsPlayer(ent)) {
		int clazz = GetEntityValue<int>(ent, eoffsets.iClass);
		if (clazz < 0 || clazz > 9) return;
		player_info_t info;
		if (!interfaces::engineClient->GetPlayerInfo(this->m_iLastTarget, &info)) return;
		AddCenterString(colors::yellow, colors::black, "Prey: %i HP %s (%s)", GetEntityValue<int>(ent, eoffsets.iHealth), tfclasses[clazz], info.name);
	} else if (IsBuilding(ent)) {
		AddCenterString(colors::yellow, colors::black, "Prey: %i HP LV %i %s", GetEntityValue<int>(ent, eoffsets.iBuildingHealth), GetEntityValue<int>(ent, eoffsets.iUpgradeLevel), GetBuildingType(ent));
	}
}

bool HAimbot::ShouldTarget(IClientEntity* entity) {
	if (!entity) return false;
	if (entity->IsDormant()) return false;
	if (IsPlayer(entity)) {
		if (IsPlayerInvulnerable(entity)) return false;
		int team = GetEntityValue<int>(entity, eoffsets.iTeamNum);
		int local = interfaces::engineClient->GetLocalPlayer();
		IClientEntity* player = interfaces::entityList->GetClientEntity(local);
		char life_state = GetEntityValue<char>(entity, eoffsets.iLifeState);
		if (life_state) return false; // TODO magic number: life state
		if (!player) return false;
		if (v_bRespectCloak->GetBool() && (GetEntityValue<int>(entity, eoffsets.iCond) & cond::cloaked)) return false;
		int health = GetEntityValue<int>(entity, eoffsets.iHealth);
		if (this->v_bCharge->GetBool() && (GetEntityValue<int>(player, eoffsets.iClass) == 2)) {
			int rifleHandle = GetEntityValue<int>(player, eoffsets.hActiveWeapon);
			IClientEntity* rifle = interfaces::entityList->GetClientEntity(rifleHandle & 0xFFF);
			if (!rifle) return false;
			float bdmg = GetEntityValue<float>(rifle, eoffsets.flChargedDamage);
			if (health > 150 && (health > (150 + bdmg) || bdmg < 15.0f)) return false;
		}
		int team_my = GetEntityValue<int>(player, eoffsets.iTeamNum);
		if (team == team_my) return false;
		Vector enemy_pos = entity->GetAbsOrigin();
		Vector my_pos = player->GetAbsOrigin();
		if (v_iMinRange->GetInt() > 0) {
			if ((enemy_pos - my_pos).Length() > v_iMinRange->GetInt()) return false;
		}
		int econd = GetEntityValue<int>(entity, eoffsets.iCond1);
		if ((econd & cond_ex::vacc_bullet)) return false;
		if (GetRelation(entity) == relation::FRIEND) return false;
		Vector resultAim;
		if (m_bProjectileMode) {
			resultAim = entity->GetAbsOrigin();
			if (!PredictProjectileAim(g_pLocalPlayer->v_Eye, entity, (hitbox)m_iHitbox, m_flProjSpeed, m_bProjArc, resultAim)) return false;
		} else {
			if (v_bMachinaPenetration->GetBool()) {
				if (GetHitboxPosition(entity, m_iHitbox, resultAim)) return false;
				if (!IsEntityVisiblePenetration(entity, v_iHitbox->GetInt())) return false;
			} else {
				if (GetHitboxPosition(entity, m_iHitbox, resultAim)) return false;
				if (!IsEntityVisible(entity, m_iHitbox)) return false;
			}
		}
		if (v_iFOV->GetBool() && (GetFov(g_pLocalPlayer->v_OrigViewangles, g_pLocalPlayer->v_Eye, resultAim) > v_iFOV->GetFloat())) return false;
		return true;
	} else if (IsBuilding(entity)) {
		int team = GetEntityValue<int>(entity, eoffsets.iTeamNum);
		if (team == g_pLocalPlayer->team) return false;
		Vector enemy_pos = entity->GetAbsOrigin();
		if (v_iMinRange->GetInt() > 0) {
			if ((enemy_pos - g_pLocalPlayer->v_Origin).Length() > v_iMinRange->GetInt()) return false;
		}
		Vector resultAim;
		if (m_bProjectileMode) {
			resultAim = entity->GetAbsOrigin();
			if (!PredictProjectileAim(g_pLocalPlayer->v_Eye, entity, (hitbox)m_iHitbox, m_flProjSpeed, m_bProjArc, resultAim)) return false;
		} else {
			//logging::Info("IsVisible?");
			if (!IsBuildingVisible(entity)) return false;
		}
		//logging::Info("IsFOV?");
		if (v_iFOV->GetBool() && (GetFov(g_pLocalPlayer->v_OrigViewangles, g_pLocalPlayer->v_Eye, resultAim) > v_iFOV->GetFloat())) return false;
		//logging::Info("Tru");
		return true;
	} else {
		return false;
	}
	return false;
}

void PredictPosition(Vector vec, IClientEntity* ent) {
	if (!ent) return;
	Vector vel = GetEntityValue<Vector>(ent, eoffsets.vVelocity);
	float latency = interfaces::engineClient->GetNetChannelInfo()->GetLatency(FLOW_OUTGOING) +
			interfaces::engineClient->GetNetChannelInfo()->GetLatency(FLOW_INCOMING);
	vec += vel * latency;
}

bool HAimbot::Aim(IClientEntity* entity, CUserCmd* cmd) {
	Vector hit;
	Vector angles;
	if (!entity) return false;
	if (IsPlayer(entity)) {
		GetHitboxPosition(entity, m_iHitbox, hit);
		PredictPosition(hit, entity);
	} else if (IsBuilding(entity)) {
		hit = GetBuildingPosition(entity);
	}
	if (v_bProjectileAimbot->GetBool()) {
		float speed = 0.0f;
		bool arc = false;
		if (GetProjectileData(g_pLocalPlayer->weapon, speed, arc)) {
			if (v_iOverrideProjSpeed->GetBool())
				speed = v_iOverrideProjSpeed->GetFloat();
			PredictProjectileAim(g_pLocalPlayer->v_Eye, entity, (hitbox)m_iHitbox, speed, arc, hit);
		}
	}
	IClientEntity* local = interfaces::entityList->GetClientEntity(interfaces::engineClient->GetLocalPlayer());
	Vector tr = (hit - g_pLocalPlayer->v_Eye);
	fVectorAngles(tr, angles);
	fClampAngle(angles);
	cmd->viewangles = angles;
	if (this->v_bSilent->GetBool()) {
		g_pLocalPlayer->bUseSilentAngles = true;
	}
	if (this->v_bAutoShoot->GetBool()) {
		if (g_pLocalPlayer->clazz == tf_class::tf_sniper) {
			if (g_pLocalPlayer->cond_0 & cond::zoomed) {
				if (this->v_iAutoShootCharge->GetBool()) {
					int rifleHandle = GetEntityValue<int>(local, eoffsets.hActiveWeapon);
					IClientEntity* rifle = interfaces::entityList->GetClientEntity(rifleHandle & 0xFFF);
					float bdmg = GetEntityValue<float>(rifle, eoffsets.flChargedDamage);
					if (bdmg < this->v_iAutoShootCharge->GetFloat()) return true;
				} else {
					if (!CanHeadshot(g_pLocalPlayer->entity)) return true;
				}
			}
		}
		cmd->buttons |= IN_ATTACK;
	}
	return true;
}

HAimbot* g_phAimbot = 0;
