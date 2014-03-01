package com.rapidminer.tools.expressions;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.rapidminer.cryptography.hashing.HashFunction;
import com.rapidminer.tools.expression.parser.JEPFunctionException;

public class HashFunctionTests {

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
	public void testDefaultHashing(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			String hash = (String) hashFunction.compute("zweiundvierzig");
			String hashTwo = (String) hashFunction.compute("zweiundvierzig");
			Assert.assertEquals(hash, hashTwo);

			String intHash = (String) hashFunction.compute(42);
			String intHashTwo = (String) hashFunction.compute(42);
			Assert.assertEquals(intHash, intHashTwo);

			String doubleHash = (String) hashFunction.compute(4.2d);
			String doubleHashTwo = (String) hashFunction.compute(4.2d);
			Assert.assertEquals(doubleHash, doubleHashTwo);

			String longHash = (String) hashFunction.compute(42L);
			String longHashTwo = (String) hashFunction.compute(42L);
			Assert.assertEquals(longHash, longHashTwo);

			String floatHash = (String) hashFunction.compute(4.2f);
			String floatHashTwo = (String) hashFunction.compute(4.2f);
			Assert.assertEquals(floatHash, floatHashTwo);
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testSaltByteArgument(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			String hash = (String) hashFunction.compute(8, "zweiundvierzig");
			String hashTwo = (String) hashFunction.compute(8, "zweiundvierzig");
			Assert.assertNotEquals(hash, hashTwo);

			String intHash = (String) hashFunction.compute(8, 42);
			String intHashTwo = (String) hashFunction.compute(8, 42);
			Assert.assertNotEquals(intHash, intHashTwo);

			String doubleHash = (String) hashFunction.compute(8, 4.2d);
			String doubleHashTwo = (String) hashFunction.compute(8, 4.2d);
			Assert.assertNotEquals(doubleHash, doubleHashTwo);

			String longHash = (String) hashFunction.compute(8, 42L);
			String longHashTwo = (String) hashFunction.compute(8, 42L);
			Assert.assertNotEquals(longHash, longHashTwo);

			String floatHash = (String) hashFunction.compute(8, 4.2f);
			String floatHashTwo = (String) hashFunction.compute(8, 4.2f);
			Assert.assertNotEquals(floatHash, floatHashTwo);
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(dataProvider = "Algorithm-Provider-Function")
	public void testSaltByteAndIterationsArguments(String algo) {
		try {
			HashFunction hashFunction = new HashFunction(algo);
			String hash = (String) hashFunction.compute(1000, 8,
					"zweiundvierzig");
			String hashTwo = (String) hashFunction.compute(1000, 8,
					"zweiundvierzig");
			Assert.assertNotEquals(hash, hashTwo);

			String intHash = (String) hashFunction.compute(1000, 8, 42);
			String intHashTwo = (String) hashFunction.compute(1000, 8, 42);
			Assert.assertNotEquals(intHash, intHashTwo);

			String doubleHash = (String) hashFunction.compute(1000, 8, 4.2d);
			String doubleHashTwo = (String) hashFunction.compute(1000, 8, 4.2d);
			Assert.assertNotEquals(doubleHash, doubleHashTwo);

			String longHash = (String) hashFunction.compute(1000, 8, 42L);
			String longHashTwo = (String) hashFunction.compute(1000, 8, 42L);
			Assert.assertNotEquals(longHash, longHashTwo);

			String floatHash = (String) hashFunction.compute(1000, 8, 4.2f);
			String floatHashTwo = (String) hashFunction.compute(1000, 8, 4.2f);
			Assert.assertNotEquals(floatHash, floatHashTwo);
		} catch (Exception e) {
			Assert.fail("Error calculcating hash for " + algo + ".", e);
		}
	}

	@Test(expectedExceptionsMessageRegExp = "Too many arguments\\..*", expectedExceptions = JEPFunctionException.class)
	public void testTooManyArguments() throws JEPFunctionException {
		HashFunction hashFunction = new HashFunction("MD5");
		hashFunction.compute(1000, 8, "42", "500");
	}

	@Test(expectedExceptionsMessageRegExp = "Missing input\\..*is required\\.", expectedExceptions = JEPFunctionException.class)
	public void testEmptyArguments() throws JEPFunctionException {
		HashFunction hashFunction = new HashFunction("MD5");
		hashFunction.compute();
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for salt size argument\\. Only numbers are allowed\\.", expectedExceptions = JEPFunctionException.class)
	public void testWrongSaltArgumentType() throws JEPFunctionException {
		HashFunction hashFunction = new HashFunction("MD5");
		hashFunction.compute("42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for salt size argument\\. Only numbers are allowed\\.", expectedExceptions = JEPFunctionException.class)
	public void testWrongSaltArgumentTypeWithIterations()
			throws JEPFunctionException {
		HashFunction hashFunction = new HashFunction("MD5");
		hashFunction.compute(1000, "42", "42");
	}

	@Test(expectedExceptionsMessageRegExp = "Wrong input type for number of iterations argument. Only numbers are allowed.", expectedExceptions = JEPFunctionException.class)
	public void testWrongIterationArgumentType() throws JEPFunctionException {
		HashFunction hashFunction = new HashFunction("MD5");
		hashFunction.compute("1000", 8, "42");
	}

}
