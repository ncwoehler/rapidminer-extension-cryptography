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

import com.rapidminer.tools.Ontology;
import com.rapidminer.tools.expression.ExpressionParsingException;
import com.rapidminer.tools.expression.FunctionDescription;
import com.rapidminer.tools.expression.internal.function.AbstractArbitraryStringInputStringOutputFunction;

/**
 * 
 * Abstract super class of all RapidMiner functions that configure and use a
 * {@link DigesterConfig}.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractHashFunction extends AbstractArbitraryStringInputStringOutputFunction {

	/**
	 * The algorithm name used to select the algorithm from the algorithm
	 * provider.
	 */
	private final String algorithm;

	/**
	 * The function name to be used from within RapidMiner.
	 */
	private String functionName;

	AbstractHashFunction(String algorithm, String functionName) {
		super(functionName, -1);
		this.algorithm = algorithm;
		this.functionName = functionName;
	}

	@Override
	public String compute(String... arguments) throws ExpressionParsingException {

		DigesterConfig config = new DigesterConfig();
		config.setAlgorithm(algorithm);

		// parse salt size from arguments
		config.setSaltSize(getSaltSize(arguments));

		// parse number of iterations from arguments
		config.setIterations(getIterations(arguments));

		return apply(config, arguments);
	}

	@Override
	protected void checkNumberOfInputs(int length) {
		// input sanity checks
		if (length < getMinArguments()) {
			String errorMessage = "Missing input. For " + getFunctionName()
					+ " at least " + getMinArguments();
			if (getMinArguments() > 1) {
				errorMessage += " arguments are required.";
			} else {
				errorMessage += " argument is required.";
			}
			throw createException(errorMessage);
		}

		if (length > getMaxArguments()) {
			throw createException("Too many arguments. For "
					+ getFunctionName() + " a maximum of " + getMaxArguments()
					+ " arguments is supported.");
		}
	}

	@Override
	public FunctionDescription getFunctionDescription() {
		// hack to override FunctionDescription internals
		return new FunctionDescription("someKey", -1, Ontology.NOMINAL) {

			@Override
			public String getDescription() {
				return getHelpText(algorithm);
			}

			@Override
			public String getGroupName() {
				return AbstractHashFunction.this.getGroupName();
			}

			@Override
			public String getDisplayName() {
				return functionName + "()";
			}

			@Override
			public String getHelpTextName() {
				return functionName;
			}

			@Override
			public String getFunctionNameWithParameters() {
				return functionName;
			}
		};
	}

	@Override
	public String getFunctionName() {
		return functionName;
	}

	private Integer getIterations(String... arguments)
			throws ExpressionParsingException {

		// If iterations are not defined use the default number of iterations
		if (arguments.length != getMaxArguments()) {
			return 1;
		}

		// get iterations from arguments (iterations is always the last
		// argument for the function, so first argument in the argument list as
		// it is provided in reverse order) and do some sanity checks
		String arg2 = arguments[0];
		int numberOfIterations = 1;
		if (arg2 != null) {
			try {
				numberOfIterations = Integer.parseInt(arg2);
			} catch(NumberFormatException e) {
				throw createException("Cannot read number of iterations: " + e.getMessage());
			}
		}
		if (numberOfIterations < 1) {
			throw createException(
					"The number of iterations has to be >= 1. Specified number of iterations: "
							+ numberOfIterations);
		}
		return numberOfIterations;
	}

	private Integer getSaltSize(String... arguments)
			throws ExpressionParsingException {

		// if no salt size is defined, return default value
		if (arguments.length < (getMaxArguments() - 1)) {
			return 0;
		}
		// look up index of salt size argument
		// salt size is expected to be the second last element in case the
		// maximum number of arguments is entered and the last argument
		// in case it is specified at all

		// last argument (arguments are provided in reverse order)
		int index = 0;
		// second last argument
		if (arguments.length == getMaxArguments()) {
			++index;
		}
		String arg1 = arguments[index];
		Integer saltSize = 8;
		if (arg1 != null) {
			try {
				saltSize = Integer.parseInt(arg1);
			} catch(NumberFormatException e) {
				throw createException("Cannot read salt size: " + e.getMessage());
			}
		}
		if (saltSize < 0) {
			throw createException("The salt size has to be >= 0. "
					+ "Specified salt size: " + saltSize);
		}
		return saltSize;
	}

	/**
	 * Apply a custom digester function with the specified {@link DigesterConfig}.
	 */
	protected abstract String apply(DigesterConfig config, String... arguments)
			throws ExpressionParsingException;

	/**
	 * Defines the maximum number of arguments for the RapidMiner function.
	 */
	protected abstract int getMaxArguments();

	/**
	 * Defines the minimum number of arguments for the RapidMiner function.
	 */
	protected abstract int getMinArguments();

	protected abstract String getGroupName();

	/**
	 * @return the help text displayed when hovering over the function button
	 */
	protected abstract String getHelpText(String algorithm);

	static ExpressionParsingException createException(String message) {
		return new ExpressionParsingException(new IllegalArgumentException(message));
	}

}
