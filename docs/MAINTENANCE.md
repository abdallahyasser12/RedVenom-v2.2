# Maintenance and verification status

This document records the maintenance practices and known implementation gaps for the repository as it exists today. It intentionally distinguishes checks that can be run locally from behavior that has not been validated in a live assessment.

## Repository layout

- `redvenom.sh` — interactive Bash orchestration script and embedded payload/response-matching routines.
- `README.md` — project overview and entry point.
- `docs/` — installation, safety, and maintenance documentation.
- `scripts/check_docs.py` — standard-library documentation and local-link checker.

## Local checks

Run these from the repository root:

```bash
bash -n redvenom.sh
python3 scripts/check_docs.py
```

If ShellCheck is installed, it is useful as an additional static review:

```bash
shellcheck redvenom.sh
```

ShellCheck findings should be reviewed rather than blindly auto-fixed; the script uses interactive prompts, background process, and several external tools. The repository does not currently publish a CI status or claim that ShellCheck is clean.

The documentation checker validates required documentation files, balanced Markdown code fences, and local Markdown links. It does not run the scanner, install third-party dependencies, validate remote URL3, or prove that instructions work on every distribution.

## Current gaps to address in future engineering work

KȊʔ؛ܙH[ٛܘٛY[ݎʊțۈ؛ۛژ؛؛ܙHڛH܈\˜ٜ]Y\݈ܝ[ݛ\݈\ș[ٛܘٙXܛܜș\؛ݙ\ٙTӌ˂̋ȊʑވݛΊʈ\و\țۈ[ٙH]ڛݜȜ[ۙYXݚ[ۜȝڝݝٛٚ[وٝۜڈؙٚX˂̋Ȋʔٜ]Y\݈ݙٝ[َʊȘۛ؝\ܙ[؞H\ș[XٙY[ȝH؜ڜ[و\و\țۈܙ\؝܋XۛݜۛYؘۛ[ٜ]Y\݈ݙٝ܈؝HۙڛKȊʔݛȚ\ۛ][ێʊȜݛ܈ژ\وڞYݝ]]ˈ[وݘ\ݝ\[]\ȝH^\ݚ[وۛݙ[ݜțو٘ۛםٛۛK؈؝\ȝ[ȘܙX][وH[ڜ]YHݛș\٘ݛܞKKȊʑ\[ٙ[؞HٙۚYڝʊțZ\ܚ[و\[ٙ[ؚY\șț۝ۛܚ\ݙ[ݛHݛ܈^Xݝ[ۈٙۜو]\ȜݘYٜȘ؛HZ\ܚ[وۛ[X[ٜ˂͋Ȋʔٜۘ܈ݛٜܚ\ʊțܝ[ۘ[ԓȘۙX[ݜ\ٜȘڛ[ܙ[ݜ؈؝\ȝ[ȝؘښ[وۛHHٜۘ܈ݘ\ݙYވH؜ڜˈ
ʑڛٚ[و؛Y][ێʊȜٜٝ؛ݚ[Z[ȘڙXڜȝ\وڛ\HݜڛوX]ښ[و[و]\݈۝وٜٜٛݙY\șYڛڝ]وݛؘٜڛ]Hۛٚ\ۘ][ۋ
ʔٜۙXژۙH\ݚ[َʊțۈؙوؘ[\݈\ۙ\܈ݜܙ[ݛH۝ٜ܈Hܘڙ\ݜ؝[ۈ݈ۛ܈Hݚ[Z[ș]Xݚ[ۈ۝][ٜ˂\و\وۛݛț[Z]][ۜˈ۝ۘZ[\ȝ]Hٜܚ]ܞH\Ș[٘YHۛٙ[KȐژ[ٙ\ȝ]Yٜ܈[Hڛݛ[؛YHۘݜٙ\ݜȘ[و]\݈ٜٜݙH^Xڝ]]ܚ^؝[ۈ۝[٘\ڙ\˂Ȉ\[ٙ[؞HXZ[ݙ[؛ؙBH[ܝ[ۛșܛۈZ\ȝ\ݜ٘[Hۚ٘ݜȘ[وٝڙ]șXXڈۚ٘݉܈ٛX\و۝\Șٙۜو\ܘY[ًH٘ۜوH\ݙYۛٜܚ[ۜȚ[ȘݙȜٜܝȝڙ[Șٚ]ڛ܈ژ[ٙ\˂ˈț۝ٛٛ܈\ً\\ݞHۛȚ[ݛȝ\Ȝٜܚ]ܞH[ۙ\܈Z\țXٛܙ\Ș[و\]Hٜܛۜژڛ]Y\Ț]وٙ[Ȝٝڙ]ٙHًXڙXڈӒH؛Y\Ș[وۘY܈Yݙ\ȝ\ܘY\ˈ[Ȝ\ݚXݛ\ˈٙٛۛH^XݜȝHۚ٘ݑ\؛ݙ\ވڛ؜ދ۝HYٙ\݈ٛۛڝH؛YHۛ[X[و؛YKH٘]^\ۘ[RH۝ڙ\Șٚ]ڛ܈[و]H[ٛ[و\ȘHٜ\؝H\[ٙ[؞H۝[٘\ދȈȔٛX\و\ؚ\[قٙۜوXۚ\ښ[وHژ[ٙN̋Ȕٝڙ]ȝHۛ\]HYو[وۛٚ\ۈۈTHٞ\ˈ\ٙ]]Kؘ[țݝ]ˈ܈ؘ[ۛٚYݜ؝[ۈڛ\Ș\و[؛YYˈݛȘ؜ڈ[ȜٙٛۛKܚYݙ\Ȝڙ[ژ[ٙ\˂̋ȔݛȘ]یȜ؜ڜ˘ڙXڗٛ؜˜XYݙ\ș؝[Y[ݘ][ۈژ[ٙ\˂͋ȔݛȔڙ[ڙXڈڙ[Ș]ؚ[XۙH[و٘ۜو[ܙ\ۛٙڛٚ[ٜ˂͋ȕ\݈ٝۜڈٚ]ڛ܈ۛH[ȘHXț܈[ݚ\ۛۙ[݈ۜȝښXڈ[݈]و^Xڝ]]ܚ^؝[ۋˈ\]H\ș؝[Y[݈ڙ[Ț[\[Y[ݘ][ۈ[Z]][ۜȘژ[ٙNșț۝ۘZ[HHۛݜۛ^\ݜȝ[ݚ[]\Ț[\[Y[ݙY[و\ݙYȈȔ݈ۚ٘[وٜܚ[ۈ۝\՚Hٜܚ]ܞH؛YH\ȘٙٛۛK]̘̋ȕH؜ڜۛݘZ[܈ۙ\Ț[ݙ\ۘ[ۛ[Y[ݜȘ[وۛܛۙH^ٜٙܚ[وțݚ\ȔٙٛۛHٜܚ[ۈXٛˈ[ݚ[HڛٛHٜܚ[ۈۛܝ[݈[وٛX\وٜۘ܈\و[ݜۙXٙ\وHٜܚ]ܞH؛YHڙ[Ȝٜٙܚ[وȝ\Ȝ۝\ؙHۘ\ڛ݈[و]ۚY[\Z[و]]ٜވ[ݙ\ۘ[XٛٜٜٛݜȘHٜ\؝[HXۚ\ڙYٛX\ً