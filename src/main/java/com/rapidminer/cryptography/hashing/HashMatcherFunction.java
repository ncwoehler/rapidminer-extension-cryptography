/*
 *  RapidMiner Cryptography Extension
 *
 *  Copyright (C) 2014 by Nils Woehler
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
package com.rapidminer.cryptography.hashing;

import com.rapidminer.tools.expression.parser.JEPFunctionException;

/**
 * 
 * A JEP function that checks whether the provided input matches a hash value
 * created by a {@link HashFunction}.
 * 
 * @author Nils Woehler
 * 
 */
public class HashMatcherFunction extends AbstractHashFunction<Boolean> {

	protected static final String PREFIX = "match_";

	public HashMatcherFunction(String functionID) {
		super(functionID, PREFIX + HashFunction.getHashFunctionName(functionID));
	}

	@Override
	protected Boolean apply(DigesterConfig config, Object... arguments)
			throws JEPFunctionException {
		Object hash = arguments[arguments.length - 2];
		if (!(hash instanceof String)) {
			throw new JEPFunctionException(
					"Wrong type for hash value. Only base64 encoded hash values are allowed!");
		}
		return Digester.INSTANCE.matches(arguments[arguments.length - 1],
				(String) hash, config);
	}

	@Override
	protected int getMaxArguments() {
		return 4;
	}

	@Override
	protected int getMinArguments() {
		return 2;
	}

	@Override
	protected String getHelpText(String algorithm) {
		return "<html><div style='width: 550px;'>Checks a value against a given BASE64 encoded "
				+ algorithm
				+ " hash. <b>This method has to use the same number of salt bytes and iterations that have been used to create the hash. Otherwise the result will always be false.</b>"
				+ "<br/>As for all hash function the default number of salt bytes is 0 and the default number of iterations is 1."
				+ "<ul>"
				+ "<li>The first parameter defines the input that should be checked against the hash. </li>"
				+ "<li>The second parameter defines the "
				+ algorithm
				+ " hash.</li>"
				+ "<li>The third parameter is optional and defines the number of bytes that should be used as salt (Default: 0, Minimum: 0).</li>"
				+ "<li>The fourth parameter is optional and defines the number of iterations (Default: 1, Minimum: 1).</li>"
				+ "</ul></div><html>";
	}

}
