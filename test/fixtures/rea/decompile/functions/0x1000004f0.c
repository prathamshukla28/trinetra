// rea decompile_all
// name: entry
// address: 0x1000004f0
// body: available
// range: 0x1000004f0-0x1000007c3 inclusive
// non_contiguous: false
// provider: Ghidra 12.1.4 (ghidra)
// analysis_profile: 066f9d6c56d7a436e2061afaa7f68aa9085572cd83e3172cf52ecd30a6101bae
// limitations: The session serves operations only after Ghidra reports default auto-analysis complete; incomplete analysis does not expose partial results.; The imported Program and temporary project are ephemeral and deleted on close. Annotation operations edit session database metadata; original executable bytes are never written.; Cancelling an active Ghidra request terminates its ephemeral database and discards session annotations. The selected target remains open; the next provider query imports the original artifact again.; Default-space addresses use lowercase 0x-prefixed hexadecimal; other address spaces use <percent-encoded-space>:0x<hex>.; macOS sessions require a matching executable Ghidra native decompiler; REA checks for it but does not build native components or change Gatekeeper quarantine state.; Pseudocode is Ghidra decompiler output, not original source and not text-equivalent to Hopper output.; External functions and functions without an analyzable body return null; other decompiler failures remain explicit.
// pseudocode: provider-specific; not original source


undefined8 entry(uint param_1,long param_2)

{
  byte *pbVar1;
  bool bVar2;
  byte bVar3;
  bool bVar4;
  undefined *puVar5;
  bool bVar6;
  bool bVar7;
  uint uVar8;
  int iVar9;
  char *pcVar10;
  size_t sVar11;
  undefined8 uVar12;
  byte bVar13;
  byte *pbVar14;
  ulong uVar15;
  byte *pbVar16;
  wchar_t local_64;
  
  pcVar10 = _getenv("POSIXLY_CORRECT");
  if ((pcVar10 == (char *)0x0) && (pcVar10 = _getenv("POSIX_PEDANTIC"), pcVar10 == (char *)0x0)) {
    pcVar10 = *(char **)(param_2 + 8);
    if (((pcVar10 == (char *)0x0) || (*pcVar10 != '-')) || (pcVar10[1] != 'n')) {
      bVar7 = false;
    }
    else {
      bVar7 = pcVar10[2] == '\0';
    }
    bVar4 = true;
  }
  else {
    bVar4 = false;
    bVar7 = false;
  }
  puVar5 = PTR____mb_cur_max_100004040;
  if (0 < (int)param_1) {
    uVar15 = 0;
    do {
      bVar2 = (bool)(bVar7 & uVar15 == 1);
      if (uVar15 == 0) {
        bVar2 = true;
      }
      if (!bVar2) {
        pbVar14 = *(byte **)(param_2 + uVar15 * 8);
        sVar11 = _strlen((char *)pbVar14);
        if (0 < (long)sVar11) {
          pbVar1 = pbVar14 + sVar11;
          do {
            local_64 = L'\0';
            uVar8 = _mbtowc(&local_64,(char *)pbVar14,(long)*(int *)puVar5);
            if ((int)uVar8 < 1) {
              _putchar((int)(char)*pbVar14);
              uVar8 = 1;
            }
            else if (local_64 == L'\\') {
              pbVar16 = pbVar14 + uVar8;
              bVar13 = *pbVar16;
              if (bVar4) {
                if (bVar13 == 99) {
LAB_1000007bc:
                  FUN_1000007c4();
                  goto LAB_1000007c0;
                }
                _putchar(0x5c);
              }
              else {
                pbVar14 = pbVar16;
                if (bVar13 < 0x66) {
                  if (bVar13 < 0x61) {
                    if (bVar13 == 0x30) {
                      bVar13 = pbVar16[1];
                      if ((bVar13 & 0xf8) == 0x30) {
                        iVar9 = 0;
                        uVar8 = 0;
                        do {
                          bVar3 = bVar13 - 0x30;
                          bVar13 = pbVar16[2];
                          bVar6 = uVar8 < 2;
                          uVar8 = uVar8 + 1;
                          iVar9 = iVar9 * 8 + (uint)bVar3;
                          pbVar16 = pbVar16 + 1;
                          pbVar14 = pbVar16;
                        } while ((bVar13 & 0xf8) == 0x30 && bVar6);
                      }
                      else {
                        iVar9 = 0;
                      }
                    }
                    else {
                      if (bVar13 != 0x5c) goto LAB_1000006ec;
                      iVar9 = 0x5c;
                    }
                  }
                  else if (bVar13 == 0x61) {
                    iVar9 = 7;
                  }
                  else if (bVar13 == 0x62) {
                    iVar9 = 8;
                  }
                  else {
                    if (bVar13 == 99) goto LAB_1000007bc;
LAB_1000006ec:
                    iVar9 = (int)(char)pbVar16[-1];
                    pbVar14 = pbVar16 + -1;
                  }
                }
                else if (bVar13 < 0x72) {
                  if (bVar13 == 0x66) {
                    iVar9 = 0xc;
                  }
                  else {
                    if (bVar13 != 0x6e) goto LAB_1000006ec;
                    iVar9 = 10;
                  }
                }
                else if (bVar13 == 0x72) {
                  iVar9 = 0xd;
                }
                else if (bVar13 == 0x74) {
                  iVar9 = 9;
                }
                else {
                  if (bVar13 != 0x76) goto LAB_1000006ec;
                  iVar9 = 0xb;
                }
                _putchar(iVar9);
                uVar8 = 1;
              }
            }
            else {
              _putwchar(local_64);
            }
            pbVar14 = pbVar14 + uVar8;
          } while (pbVar14 < pbVar1);
        }
      }
      bVar6 = bVar7;
      if (uVar15 != param_1 - 1) {
        bVar6 = true;
      }
      if (bVar6) {
        if (uVar15 == param_1 - 1) {
          bVar2 = true;
        }
        if (!bVar2) {
          iVar9 = 0x20;
          goto LAB_100000730;
        }
      }
      else {
        iVar9 = 10;
LAB_100000730:
        _putchar(iVar9);
      }
      iVar9 = _fflush(*(FILE **)PTR____stdoutp_100004048);
      if (iVar9 != 0) {
LAB_1000007c0:
        FUN_1000007f8();
        iVar9 = _fflush(*(FILE **)PTR____stdoutp_100004048);
        if (iVar9 == 0) {
                    /* WARNING: Subroutine does not return */
          _exit(0);
        }
        _err(1,"fflush");
        _err(1,"fflush");
                    /* WARNING: Could not recover jumptable at 0x000100000820. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        uVar12 = (*(code *)PTR__err_100004000)();
        return uVar12;
      }
      uVar15 = uVar15 + 1;
    } while (uVar15 != param_1);
  }
  return 0;
}

