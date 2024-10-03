package app.revanced.patches.thunderbird.auth

import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.InstructionExtensions.addInstruction
import app.revanced.patcher.extensions.InstructionExtensions.getInstruction
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchException
import app.revanced.patcher.patch.annotation.CompatiblePackage
import app.revanced.patcher.patch.annotation.Patch
import app.revanced.patcher.patch.options.PatchOption.PatchExtensions.stringPatchOption
import app.revanced.patches.thunderbird.auth.fingerprints.OAuthMicrosoftFingerprint
import app.revanced.util.resultOrThrow
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction

@Patch(
    name = "Spoof Microsoft OAuth",
    description = "Spoof clientID and redirectURI used in OAuth with Microsoft Office365 servers.",
    compatiblePackages = [
        CompatiblePackage("com.fsck.k9"),
        CompatiblePackage("net.thunderbird.android"),
        CompatiblePackage("net.thunderbird.android.beta"),
        CompatiblePackage("net.thunderbird.android.daily")
    ]
)
object SpoofClientPatch : BytecodePatch(fingerprints = setOf(OAuthMicrosoftFingerprint)) {
    private var newClientId by stringPatchOption(
        key = "newClientId",
        title = "Client ID",
        description = "New client ID used for OAuth",
        required = true
    )

    private var newRedirectURI by stringPatchOption(
        key = "newRedirectURI",
        title = "Redirect URI",
        description = "New URI to which the authorization server will redirect with access token"
    )

    override fun execute(context: BytecodeContext) {
        val clientId = newClientId!!
        val result = OAuthMicrosoftFingerprint.resultOrThrow()
        val regRangeIndex = result.scanResult.patternScanResult!!.startIndex

        result.mutableMethod.apply {
            val inst = getInstruction<RegisterRangeInstruction>(regRangeIndex)
            if (inst.registerCount != 6)
                throw PatchException("OAuthConfiguration constructor call should have 6 registers")

            val clientIdReg = inst.startRegister + 1
            if (!newRedirectURI.isNullOrBlank()) {
                val redirectURIReg = clientIdReg + 4
                val redirectURI = newRedirectURI!!
                addInstruction(regRangeIndex, "const-string v$redirectURIReg, \"$redirectURI\"")
            }
            addInstruction(regRangeIndex, "const-string v$clientIdReg, \"$clientId\"")
        }
    }
}
