package org.matrix.vector.nativebridge

import android.content.res.Resources

object ResourcesHook {
    @JvmStatic external fun initXResourcesNative(): Boolean

    @JvmStatic external fun makeInheritable(clazz: Class<*>): Boolean

    @JvmStatic
    external fun buildDummyClassLoader(
        parent: ClassLoader,
        resourceSuperClass: String,
        typedArraySuperClass: String,
    ): ClassLoader

    // CAREME: writes the dummy-superclass dex to a real file (in-memory dex can't define a class
    // that extends a concrete framework class on this ART 8.1). Returns true on success.
    @JvmStatic
    external fun writeDummyDex(
        path: String,
        resourceSuperClass: String,
        typedArraySuperClass: String,
    ): Boolean

    // Not @FastNative: the implementation walks a whole binary XML document and calls back into
    // Java once per attribute, and a fast transition leaves the thread runnable for all of it, so
    // anything waiting to suspend threads waits for the document.
    @JvmStatic
    external fun rewriteXmlReferencesNative(parserPtr: Long, origRes: Any, repRes: Resources)
}
