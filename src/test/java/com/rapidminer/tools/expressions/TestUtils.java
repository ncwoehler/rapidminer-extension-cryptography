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
package com.rapidminer.tools.expressions;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;


class TestUtils {

	static Object[][] parameterIntTestProvider() {
		final List<String> algos = new ArrayList<String>(
				Security.getAlgorithms("MessageDigest"));
		Collections.sort(algos);
		Object[][] arguments = new Object[algos.size()][1];
		for (int i = 0; i < arguments.length; ++i) {
			arguments[i][0] = algos.get(i);
		}
		return arguments;
	}
}
