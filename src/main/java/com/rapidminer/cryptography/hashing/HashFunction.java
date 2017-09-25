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
package com.rapidminer.cryptography.hashing;

import com.rapidminer.tools.expression.ExpressionParsingException;

/**
 * 
 * A function that calculate the hash value of the provided input.
 * 
 * @author Nils Woehler
 * 
 */
public class HashFunction extends AbstractHashFunction {

	public static final String FUNCTION_GROUP = "Hash Functions";

	public HashFunction(String algorithm) {
		super(algorithm, getHashFunctionName(algorithm));
	}

	/**
	 * @return the function name to be used from within RapidMiner
	 */
	static String getHashFunctionName(String functionID) {
		return functionID.replace("-", "").toLowerCase();
	}

	@Override
	protected String apply(DigesterConfig config, String... arguments)
			throws ExpressionParsingException {
		return DigesterProvider.INSTANCE.digest(arguments[arguments.length - 1], config);
	}

	@Override
	protected String getHelpText(String algorithm) {
		return "Calculates the BASE64 encoded " + algorithm + " hash value of the specified input. " 
				+ "The default number of salt bytes is 0 and the default number of iterations is 1."
				+ "The default values will return equal results for consecutive calls with the same input."
				+ "Increasing the number of salt bytes (e.g. to 8) will return different results consecutive calls with the same input."
				+ "To check whether two hashes created with at least one salt byte are equal use '"
				+ HashMatcherFunction.PREFIX + getFunctionName() + "'. "
				+ "The first parameter defines the input for which the hash value should be calculated."
				+ "The second parameter is optional and defines the number of bytes that should be used as salt (Default: 0, Minimum: 0)."
				+ "The third parameter is optional and defines the number of iterations (Default: 1, Minimum: 1).";
	}

	@Override
	protected int getMaxArguments() {
		return 3;
	}

	@Override
	protected int getMinArguments() {
		return 1;
	}

	@Override
	protected String getGroupName() {
		return FUNCTION_GROUP;
	}
}
