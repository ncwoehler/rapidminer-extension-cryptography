/**
 * RapidMiner Cryptography Extension
 *
 * Copyright (C) 2014-2014 by Nils Woehler
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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.rapidminer.cryptography.hashing.HashFunction;
import com.rapidminer.cryptography.hashing.HashMatcherFunction;
import com.rapidminer.tools.expression.parser.JEPFunctionException;

public class HashMatcherFunctionTests {

	// This function will provide the algorithm names
	@DataProvider(name = "Algorithm-Provider-Function")
	public Object[][] parameterIntTestProvider() {
		final List<String> algos = new ArrayList<String>(
				Security.getAlgorithms("MessageDigest"));
		Collections.sort(algos);
		Object[][] arguments = new Object[algos.size()][1];
		for (int i = 0; i < arguments.length; ++i) {
			arguments[i][0] = algos.get(i);
		}
		return arguments;
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testDefaultMatching(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			HashMatcherFunction matcher = new HashMatcherFunction(algo);
			String hash = (String) hashFunction.compute("zweiundvierzig");
			Object matches = matcher.compute(hash, "zweiundvierzig");
			Assert.assertTrue(
					(Boolean) matches,
					"String input hash does not match");

			String intHash = (String) hashFunction.compute(42);
			Assert.assertTrue((Boolean) matcher.compute(intHash, 42),
					"Int input hash does not match");

			String doubleHash = (String) hashFunction.compute(4.2d);
			Assert.assertTrue((boolean) matcher.compute(doubleHash, 4.2d),
					"Double input hash does not match");

			String longHash = (String) hashFunction.compute(42L);
			Assert.assertTrue((Boolean) matcher.compute(longHash, 42L),
					"Long input hash does not match");

			String floatHash = (String) hashFunction.compute(4.2f);
			Assert.assertTrue((Boolean) matcher.compute(floatHash, 4.2f),
					"Float input hash does not match");
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testMatching(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			HashMatcherFunction matcher = new HashMatcherFunction(algo);
			String hash = (String) hashFunction.compute(1000, 8,
					"zweiundvierzig");
			Assert.assertTrue(
					(boolean) matcher.compute(1000, 8, hash, "zweiundvierzig"),
					"String input hash does not match");

			String intHash = (String) hashFunction.compute(1000, 8, 42);
			Assert.assertTrue((boolean) matcher.compute(1000, 8, intHash, 42),
					"Int input hash does not match");

			String doubleHash = (String) hashFunction.compute(1000, 8, 4.2d);
			Assert.assertTrue(
					(boolean) matcher.compute(1000, 8, doubleHash, 4.2d),
					"Double input hash does not match");

			String longHash = (String) hashFunction.compute(1000, 8, 42L);
			Assert.assertTrue((boolean) matcher.compute(1000, 8, longHash, 42L),
					"Long input hash does not match");

			String floatHash = (String) hashFunction.compute(1000, 8, 4.2f);
			Assert.assertTrue(
					(boolean) matcher.compute(1000, 8, floatHash, 4.2f),
					"Float input hash does not match");
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(expectedExceptionsMessageRegExp = "Too many arguments\\..*", expectedExceptions = JEPFunctionException.class)
	public void testTooManyArguments() throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute(1000, 8, "42", "500", "5001");
	}

	@Test(expectedExceptionsMessageRegExp = "Missing input\\..*are required\\.", expectedExceptions = JEPFunctionException.class)
	public void testEmptyArguments() throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute();
	}

	@Test(expectedExceptionsMessageRegExp = "Missing input\\..*are required\\.", expectedExceptions = JEPFunctionException.class)
	public void testOneArgument() throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("42");
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for salt size argument\\. Only numbers are allowed\\.", expectedExceptions = JEPFunctionException.class)
	public void testWrongSaltArgumentType() throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("42", "42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for salt size argument\\. Only numbers are allowed\\.", expectedExceptions = JEPFunctionException.class)
	public void testWrongSaltArgumentTypeWithIterations()
			throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute(1000, "42", "42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for number of iterations argument. Only numbers are allowed.", expectedExceptions = JEPFunctionException.class)
	public void testWrongIterationArgumentType() throws JEPFunctionException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("1000", 8, "42", "42");
	}

}
