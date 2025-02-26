#include "LookupFilters.h"
#include "LookupNPC.h"

namespace Filter
{
	Data::Data(StringFilters a_strings, FormFilters a_formFilters, LevelFilters a_level, Traits a_traits, PercentChance a_chance) :
		strings(std::move(a_strings)),
		forms(std::move(a_formFilters)),
		levels(std::move(a_level)),
		traits(a_traits),
		chance(a_chance / 100)
	{
		hasLeveledFilters = HasLevelFiltersImpl();
	}

	Result Data::passed_string_filters(const NPCData& a_npcData) const
	{
		if (!strings.ALL.empty() && !a_npcData.HasStringFilter(strings.ALL, true)) {
			return Result::kFail;
		}

		if (!strings.NOT.empty() && a_npcData.HasStringFilter(strings.NOT)) {
			return Result::kFail;
		}

		if (!strings.MATCH.empty() && !a_npcData.HasStringFilter(strings.MATCH)) {
			return Result::kFail;
		}

		if (!strings.ANY.empty() && !a_npcData.ContainsStringFilter(strings.ANY)) {
			return Result::kFail;
		}

		return Result::kPass;
	}

	Result Data::passed_form_filters(const NPCData& a_npcData) const
	{
		if (!forms.ALL.empty() && !a_npcData.HasFormFilter(forms.ALL, true)) {
			return Result::kFail;
		}

		if (!forms.NOT.empty() && a_npcData.HasFormFilter(forms.NOT)) {
			return Result::kFail;
		}

		if (!forms.MATCH.empty() && !a_npcData.HasFormFilter(forms.MATCH)) {
			return Result::kFail;
		}

		return Result::kPass;
	}

	Result Data::passed_level_filters(const NPC::Data& a_npcData) const
	{
		// Actor Level
		if (!levels.actorLevel.IsInRange(a_npcData.GetLevel())) {
			return Result::kFail;
		}

		const auto npc = a_npcData.GetNPC();

		// Skill Level
		for (auto& [skillType, skillRange] : levels.skillLevels) {
			if (!skillRange.IsInRange(npc->playerSkills.values[skillType])) {
				return Result::kFail;
			}
		}

		if (const auto npcClass = npc->npcClass) {
			const auto& skillWeights = npcClass->data.skillWeights;

			// Skill Weight
			for (auto& [skillType, skillRange] : levels.skillWeights) {
				std::uint8_t skillWeight;

				using Skill = RE::TESNPC::Skills;
				switch (skillType) {
				case Skill::kOneHanded:
					skillWeight = skillWeights.oneHanded;
					break;
				case Skill::kTwoHanded:
					skillWeight = skillWeights.twoHanded;
					break;
				case Skill::kMarksman:
					skillWeight = skillWeights.archery;
					break;
				case Skill::kBlock:
					skillWeight = skillWeights.block;
					break;
				case Skill::kSmithing:
					skillWeight = skillWeights.smithing;
					break;
				case Skill::kHeavyArmor:
					skillWeight = skillWeights.heavyArmor;
					break;
				case Skill::kLightArmor:
					skillWeight = skillWeights.lightArmor;
					break;
				case Skill::kPickpocket:
					skillWeight = skillWeights.pickpocket;
					break;
				case Skill::kLockpicking:
					skillWeight = skillWeights.lockpicking;
					break;
				case Skill::kSneak:
					skillWeight = skillWeights.sneak;
					break;
				case Skill::kAlchemy:
					skillWeight = skillWeights.alchemy;
					break;
				case Skill::kSpeechcraft:
					skillWeight = skillWeights.speech;
					break;
				case Skill::kAlteration:
					skillWeight = skillWeights.alteration;
					break;
				case Skill::kConjuration:
					skillWeight = skillWeights.conjuration;
					break;
				case Skill::kDestruction:
					skillWeight = skillWeights.destruction;
					break;
				case Skill::kIllusion:
					skillWeight = skillWeights.illusion;
					break;
				case Skill::kRestoration:
					skillWeight = skillWeights.restoration;
					break;
				case Skill::kEnchanting:
					skillWeight = skillWeights.enchanting;
					break;
				default:
					continue;
				}

				if (!skillRange.IsInRange(skillWeight)) {
					return Result::kFail;
				}
			}
		}

		return Result::kPass;
	}

	Result Data::passed_trait_filters(const NPCData& a_npcData) const
	{
		auto npc = a_npcData.GetNPC();

		// Traits
		if (traits.sex && npc->GetSex() != *traits.sex) {
			return Result::kFail;
		}
		if (traits.unique && npc->IsUnique() != *traits.unique) {
			return Result::kFail;
		}
		if (traits.summonable && npc->IsSummonable() != *traits.summonable) {
			return Result::kFail;
		}
		if (traits.child && a_npcData.IsChild() != *traits.child) {
			return Result::kFail;
		}
		if (traits.leveled && a_npcData.IsLeveled() != *traits.leveled) {
			return Result::kFail;
		}
		if (traits.teammate && a_npcData.IsTeammate() != *traits.teammate) {
			return Result::kFail;
		}
		if (traits.startsDead && a_npcData.IsDead() != *traits.startsDead) {
			return Result::kFail;
		}

		return Result::kPass;
	}

	bool Data::HasLevelFilters() const
	{
		return hasLeveledFilters;
	}

	bool Data::HasLevelFiltersImpl() const
	{
		const auto& [actorLevel, skillLevels, _] = levels;

		if (actorLevel.IsValid()) {
			return true;
		}

		return std::ranges::any_of(skillLevels, [](const auto& skillPair) {
			auto& [skillType, skillRange] = skillPair;
			return skillRange.IsValid();
		});
	}

	Result Data::PassedFilters(const NPCData& a_npcData) const
	{
		// Fail chance first to avoid running unnecessary checks
		if (chance < 1) {
			const auto randNum = RNG().generate();
			if (randNum > chance) {
				return Result::kFailRNG;
			}
		}

		if (passed_string_filters(a_npcData) == Result::kFail) {
			return Result::kFail;
		}

		if (passed_form_filters(a_npcData) == Result::kFail) {
			return Result::kFail;
		}

		if (passed_level_filters(a_npcData) == Result::kFail) {
			return Result::kFail;
		}

		return passed_trait_filters(a_npcData);
	}
}
