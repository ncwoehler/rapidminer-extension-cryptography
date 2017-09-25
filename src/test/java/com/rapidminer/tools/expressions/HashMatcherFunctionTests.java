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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.rapidminer.cryptography.hashing.HashFunction;
import com.rapidminer.cryptography.hashing.HashMatcherFunction;
import com.rapidminer.tools.expression.ExpressionParsingException;


public class HashMatcherFunctionTests {

	// This function will provide the algorithm names
	@DataProvider(name = "Algorithm-Provider-Function")
	public Object[][] parameterIntTestProvider() {
		return TestUtils.parameterIntTestProvider();
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testDefaultMatching(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			HashMatcherFunction matcher = new HashMatcherFunction(algo);
			String hash = hashFunction.compute("zweiundvierzig");
			String matches = matcher.compute(hash, "zweiundvierzig");
			Assert.assertTrue(
					Boolean.valueOf(matches),
					"String input hash does not match");
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testMatching(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			HashMatcherFunction matcher = new HashMatcherFunction(algo);
			String hash = hashFunction.compute("1000", "8", "zweiundvierzig");
			Assert.assertTrue(
					 Boolean.valueOf(matcher.compute("1000", "8", hash, "zweiundvierzig")),
					"String input hash does not match");
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(expectedExceptionsMessageRegExp = "Cannot read salt size: For input string: \"asf\"", expectedExceptions = ExpressionParsingException.class)
	public void testWrongSaltArgumentType() throws ExpressionParsingException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("asf", "42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Cannot read salt size: For input string: \"asdf\"", expectedExceptions = ExpressionParsingException.class)
	public void testWrongSaltArgumentTypeWithIterations()
			throws ExpressionParsingException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("1000", "asdf", "42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Cannot read number of iterations: For input string: \"asdf\"", expectedExceptions = ExpressionParsingException.class)
	public void testWrongIterationArgumentType() throws ExpressionParsingException {
		HashMatcherFunction hashFunction = new HashMatcherFunction("MD5");
		hashFunction.compute("asdf", "42", "42", "42");
	}

}
