"""Birlesik zaman cizelgesi: MFTECmd/RECmd/EvtxECmd/PECmd CSV ciktilarinin
normallestirilip kronolojik olarak birlestirilmesi.

Hicbir test gercek bir EZ Tools ikilisi calistirmaz -- CSV fixture'lari
gercek MFTECmd/RECmd/EvtxECmd/PECmd 2026.5.0 (net9) ciktilarindan alinan
GERCEK sutun basliklarini kullanir (gercek bir $MFT ornegi, NTUSER.DAT
registry kovani, UACME_59_Sysmon.evtx ve bir NOTEPAD.EXE prefetch ornegine
karsi calistirilarak dogrulandi, bkz. docs/aldigim_kararlar.md -> "Birlesik
zaman cizelgesi"). Router'in gercek dosya adlandirma deseni de (zaman
damgali "<...>_Output.csv" / PECmd icin ayrica "<...>_Output_Timeline.csv")
fixture dosya adlarinda BIREBIR korunuyor.
"""

from datetime import datetime, timezone

from triagechain.reporting.timeline import build_timeline
from triagechain.router.models import ProcessedArtifact, RoutingManifest

NOW = datetime(2026, 6, 7, 22, 0, 0, tzinfo=timezone.utc)


def _artifact(tool, output_dir, source_path="C:/kaynak/x"):
    return ProcessedArtifact(
        artifact_type_id="x", tool=tool, source_path=source_path, output_dir=str(output_dir),
        exit_code=0, stdout_log_path="", stderr_log_path="", duration_seconds=0.1,
        processed_at_utc=NOW,
    )


def _routing(*artifacts):
    return RoutingManifest(case_id="CASE-X", started_at_utc=NOW, processed=list(artifacts))


def test_mftecmd_expands_macb_timestamps_into_separate_events(tmp_path):
    csv_path = tmp_path / "20260101000000_MFTECmd_$MFT_Output.csv"
    header = (
        "EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,ParentPath,"
        "FileName,Extension,FileSize,ReferenceCount,ReparseTarget,IsDirectory,HasAds,IsAds,"
        "SI<FN,uSecZeros,Copied,SiFlags,NameType,Created0x10,Created0x30,LastModified0x10,"
        "LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,"
        "LastAccess0x30,UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,"
        "ObjectIdFileDroid,LoggedUtilStream,ZoneIdContents,SourceFile,ResidentDataBase64,"
        "ResidentDataHex,ResidentDataASCII\n"
    )
    row = (
        "10,1,True,5,5,.\\Pictures,McCoy.jpg,.jpg,1024,1,,False,False,False,False,False,"
        "False,,DosWindows,"
        "1995-07-01 15:30:00.0000000,,"  # Created0x10, Created0x30
        "1995-07-01 15:32:34.0000000,,"  # LastModified0x10, LastModified0x30
        "1995-07-01 15:33:00.0000000,,"  # LastRecordChange0x10, LastRecordChange0x30
        ",,"  # LastAccess0x10 BOS -- bu MACB harfi olay URETMEMELI
        "0,123,256,,,,samples/mft,,,\n"
    )
    csv_path.write_text(header + row, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("mftecmd", tmp_path)))

    # LastAccess0x10 bos oldugu icin 4 degil 3 olay uretilmeli.
    assert len(events) == 3
    activities = {e.activity for e in events}
    assert activities == {"B", "M", "C"}
    modified = next(e for e in events if e.activity == "M")
    assert modified.timestamp == "1995-07-01 15:32:34.0000000"
    assert modified.detail == ".\\Pictures\\McCoy.jpg"
    assert modified.tool == "mftecmd"


def test_pecmd_reads_its_own_timeline_csv_not_the_main_csv(tmp_path):
    # PECmd'nin ANA CSV'si de ayni dizinde durur ama _parse_pecmd SADECE
    # _Output_Timeline.csv'yi okumali -- yanlislikla ana CSV'yi RunTime
    # sutunu yokken parse edip sessizce 0 olay uretmemeli.
    (tmp_path / "20260101000000_PECmd_Output.csv").write_text(
        "Note,SourceFilename,ExecutableName,RunCount\n,notepad.pf,NOTEPAD.EXE,2\n",
        encoding="utf-8-sig",
    )
    (tmp_path / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n"
        "2019-06-05 19:23:00,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n"
        "2019-06-05 19:55:04,\\VOLUME{x}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE\n",
        encoding="utf-8-sig",
    )

    events = build_timeline(_routing(_artifact("pecmd", tmp_path)))

    assert len(events) == 2
    assert {e.timestamp for e in events} == {"2019-06-05 19:23:00", "2019-06-05 19:55:04"}
    assert all(e.tool == "pecmd" and "NOTEPAD.EXE" in e.detail for e in events)


def test_evtxecmd_uses_mapdescription_falls_back_to_event_id(tmp_path):
    csv_path = tmp_path / "20260101000000_EvtxECmd_Output.csv"
    header = (
        "RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,Channel,ProcessId,"
        "ThreadId,Computer,ChunkNumber,UserId,MapDescription,UserName,RemoteHost,"
        "PayloadData1,PayloadData2,PayloadData3,PayloadData4,PayloadData5,PayloadData6,"
        "ExecutableInfo,HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload\n"
    )
    with_map = (
        "1,2164891,2020-10-05 20:43:58.4505228,10,Info,Microsoft-Windows-Sysmon,"
        "Microsoft-Windows-Sysmon/Operational,1,2,WS-01,0,,ProcessAccess,,,,,,,,,,"
        "False,sample.evtx,Classic,0,{}\n"
    )
    without_map = (
        "2,2164892,2020-10-05 20:43:58.4513146,1,Info,Microsoft-Windows-Sysmon,"
        "Microsoft-Windows-Sysmon/Operational,1,2,WS-01,0,,,,,,,,,,,"
        "False,sample.evtx,Classic,0,{}\n"
    )
    csv_path.write_text(header + with_map + without_map, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("evtxecmd", tmp_path)))

    assert len(events) == 2
    described = next(e for e in events if e.activity == "10")
    assert described.description == "ProcessAccess"
    assert "Microsoft-Windows-Sysmon" in described.detail
    fallback = next(e for e in events if e.activity == "1")
    assert fallback.description == "Olay 1"


def test_recmd_deduplicates_by_key_path_and_timestamp(tmp_path):
    csv_path = tmp_path / "20260101000000_RECmd_Batch_DFIRBatch_Output.csv"
    header = (
        "HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,ValueData,"
        "ValueData2,ValueData3,Comment,Recursive,Deleted,LastWriteTimestamp,"
        "PluginDetailFile\n"
    )
    # Ayni anahtarin ALTINDAKI iki farkli deger -- gercek RECmd ciktisinda
    # oldugu gibi AYNI LastWriteTimestamp'i tasiyor (bkz. modul dokstring'i).
    same_key_1 = (
        "NTUSER.DAT,NtUser,MountPoints2,Devices,"
        "Software\\Microsoft\\Explorer\\MountPoints2,_LabelFromReg,RegSz,User drive,,,"
        "Mount Points,True,False,2014-05-20 14:23:55.4574741,\n"
    )
    same_key_2 = (
        "NTUSER.DAT,NtUser,MountPoints2,Devices,"
        "Software\\Microsoft\\Explorer\\MountPoints2,_LabelFromDesktopINI,RegSz,,,,"
        "Mount Points,True,False,2014-05-20 14:23:55.4574741,\n"
    )
    different_key = (
        "NTUSER.DAT,NtUser,System Info,System Info,"
        "Software\\Microsoft\\Windows Media\\WMSDK,ComputerName,RegSz,HAXOR4,,,"
        "Computer name,False,False,2014-05-20 14:19:40.2296199,\n"
    )
    csv_path.write_text(header + same_key_1 + same_key_2 + different_key, encoding="utf-8-sig")

    events = build_timeline(_routing(_artifact("recmd", tmp_path)))

    # 3 deger satiri var ama sadece 2 BENZERSIZ (KeyPath, LastWriteTimestamp) cifti.
    assert len(events) == 2
    assert {e.description for e in events} == {"MountPoints2", "System Info"}


def test_missing_output_csv_is_not_an_error(tmp_path):
    """Bir arac hic calismamis/cikti uretmemis olabilir -- olumcul degil,
    sadece o kaynaktan hic olay gelmez (bkz. modul dokstring'i)."""
    events = build_timeline(_routing(_artifact("mftecmd", tmp_path)))
    assert events == []


def test_unknown_tool_name_is_silently_skipped(tmp_path):
    events = build_timeline(_routing(_artifact("bilinmeyen_arac", tmp_path)))
    assert events == []


def test_events_from_multiple_tools_are_merged_and_sorted_chronologically(tmp_path):
    mft_dir, pf_dir = tmp_path / "mft", tmp_path / "pf"
    mft_dir.mkdir()
    pf_dir.mkdir()
    (mft_dir / "20260101000000_MFTECmd_$MFT_Output.csv").write_text(
        "FileName,ParentPath,Created0x10,LastModified0x10,LastRecordChange0x10,LastAccess0x10\n"
        "old.txt,.,2020-01-01 00:00:00.0000000,,,\n",
        encoding="utf-8-sig",
    )
    (pf_dir / "20260101000000_PECmd_Output_Timeline.csv").write_text(
        "RunTime,ExecutableName\n2025-01-01 00:00:00,APP.EXE\n", encoding="utf-8-sig",
    )

    events = build_timeline(
        _routing(_artifact("pecmd", pf_dir), _artifact("mftecmd", mft_dir))
    )

    assert [e.tool for e in events] == ["mftecmd", "pecmd"]
    assert events[0].timestamp < events[1].timestamp
