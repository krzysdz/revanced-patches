package app.revanced.patches.thunderbird.auth.fingerprints

import app.revanced.patcher.extensions.or
import app.revanced.patcher.fingerprint.MethodFingerprint
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcode

internal object OAuthMicrosoftFingerprint : MethodFingerprint(
    returnType = "Lkotlin/Pair",
    opcodes = listOf(
        Opcode.INVOKE_DIRECT_RANGE,
        Opcode.INVOKE_STATIC,
        Opcode.MOVE_RESULT_OBJECT,
        Opcode.RETURN_OBJECT
    ),
    strings = listOf("https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
    customFingerprint = { methodDef, classDef ->
        classDef.type.endsWith("OAuthConfigurationFactory;") && methodDef.name == "createMicrosoftConfiguration" }
)
