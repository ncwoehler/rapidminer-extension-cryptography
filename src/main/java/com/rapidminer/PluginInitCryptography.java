/*
 * RapidMiner Cryptography Extension
 *
 * Copyright (C) 2014-2017 by Nils Woehler
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 */
package com.rapidminer;

import java.util.Collections;
import java.util.List;

import com.rapidminer.cryptography.BCAlgorithmProvider;
import com.rapidminer.cryptography.hashing.HashFunction;
import com.rapidminer.cryptography.hashing.HashMatcherFunction;
import com.rapidminer.gui.MainFrame;
import com.rapidminer.tools.expression.Constant;
import com.rapidminer.tools.expression.ExpressionParserModule;
import com.rapidminer.tools.expression.ExpressionRegistry;
import com.rapidminer.tools.expression.Function;


/**
 * This class provides hooks for initialization.
 * 
 * @author Sebastian Land
 */
public class PluginInitCryptography {


	/**
	 * This method will be called directly after the extension is initialized.
	 * This is the first hook during start up. No initialization of the
	 * operators or renderers has taken place when this is called.
	 */
	public static void initPlugin() {
		registerHashFunctions();
	}

	private static void registerHashFunctions() {
		for (String algo : BCAlgorithmProvider.INSTANCE.getHashFunctions()) {

			ExpressionParserModule module = new ExpressionParserModule() {

				@Override
				public String getKey() {
					return HashFunction.FUNCTION_GROUP;
				}

				@Override
				public List<Function> getFunctions() {
					return Collections.singletonList(new HashFunction(algo));
				}

				@Override
				public List<Constant> getConstants() {
					return Collections.emptyList();
				}
			};
			ExpressionRegistry.INSTANCE.register(module);

			ExpressionParserModule matcherModule = new ExpressionParserModule() {

				@Override
				public String getKey() {
					return HashMatcherFunction.FUNCTION_GROUP;
				}

				@Override
				public List<Function> getFunctions() {
					return Collections.singletonList(new HashMatcherFunction(algo));
				}

				@Override
				public List<Constant> getConstants() {
					return Collections.emptyList();
				}
			};
			ExpressionRegistry.INSTANCE.register(matcherModule);
		}
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
