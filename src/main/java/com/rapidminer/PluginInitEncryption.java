/*
 *  RapidMiner Encryption Extension
 *
 *  Copyright (C) 2014 by Nils Wöhler
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;

import com.rapidminer.gui.MainFrame;
import com.rapidminer.repository.RepositoryException;
import com.rapidminer.tools.FileSystemService;
import com.rapidminer.tools.Tools;

/**
 * This class provides hooks for initialization
 * 
 * @author Sebastian Land
 */
public class PluginInitEncryption {

	public static final String BC_JAR_NAME = "bcprov-jdk15on-150.jar";

	/**
	 * This method will be called directly after the extension is initialized.
	 * This is the first hook during start up. No initialization of the
	 * operators or renderers has taken place when this is called.
	 */
	public static void initPlugin() {
		try {
			File rapidMinerHome = FileSystemService.getUserRapidMinerDir();
			File encryptionDir = new File(rapidMinerHome, "encryption-provider");
			if (!encryptionDir.exists()) {
				encryptionDir.mkdir();
			}
			File bcprovider = new File(encryptionDir, BC_JAR_NAME);
			if (!bcprovider.exists()) {
				storeBCProviderToDisk(bcprovider);
			}

			// register bouncy castle provider to plugin classloader
			registerBCProviderJar(bcprovider,
					(URLClassLoader) PluginInitEncryption.class
							.getClassLoader());
		} catch (IOException | RepositoryException e) {
			throw new RuntimeException("Error loading BC provider jar.", e);
		}
	}

	/**
	 * Register specified .jar to provided class loader.
	 */
	private static void registerBCProviderJar(File jarFile,
			URLClassLoader classLoader) throws IOException {
		Class<?> sysclass = URLClassLoader.class;

		try {
			Method method = sysclass.getDeclaredMethod("addURL", URL.class);
			method.setAccessible(true);
			method.invoke(classLoader, new Object[] { jarFile.toURI().toURL() });
		} catch (Throwable t) {
			t.printStackTrace();
			throw new IOException(
					"Error, could not add URL to system classloader");
		}
	}

	/**
	 * Stores BouncyCastle provider jar from resources to disk.
	 */
	private static void storeBCProviderToDisk(File outputFile)
			throws IOException, RepositoryException {
		InputStream bcInput = Tools.getResourceInputStream("providers/"
				+ BC_JAR_NAME);
		Tools.copyStreamSynchronously(bcInput,
				new FileOutputStream(outputFile), true);
	}

	/**
	 * This method is called during start up as the second hook. It is called
	 * before the gui of the mainframe is created. The Mainframe is given to
	 * adapt the gui. The operators and renderers have been registered in the
	 * meanwhile.
	 */
	public static void initGui(MainFrame mainframe) {
	}

	/**
	 * The last hook before the splash screen is closed. Third in the row.
	 */
	public static void initFinalChecks() {
	}

	/**
	 * Will be called as fourth method, directly before the UpdateManager is
	 * used for checking updates. Location for exchanging the UpdateManager. The
	 * name of this method unfortunately is a result of a historical typo, so
	 * it's a little bit misleading.
	 */
	public static void initPluginManager() {
	}
}
