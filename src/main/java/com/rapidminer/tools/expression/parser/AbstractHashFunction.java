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
package com.rapidminer.tools.expression.parser;

/**
 * 
 * Abstract super class of all RapidMiner functions that configure and use a
 * {@link DigesterConfig}.
 * 
 * @author Nils Woehler
 * 
 */
public abstract class AbstractHashFunction<T> implements Function {

	/**
	 * The algorithm name used to select the algorithm from the algorithm
	 * provider.
	 */
	private final String algorithm;

	/**
	 * The function name to be used from within RapidMiner.
	 */
	private String functionName;

	public AbstractHashFunction(String algorithm, String functionName) {
		this.algorithm = algorithm;
		this.functionName = functionName;
	}

	@Override
	public Object compute(Object... arguments) throws JEPFunctionException {

		// input sanity checks
		if (arguments.length < getMinArguments()) {
			String errorMessage = "Missing input. For " + getFunctionName()
					+ " at least " + getMinArguments();
			if (getMinArguments() > 1) {
				errorMessage += " arguments are required.";
			} else {
				errorMessage += " argument is required.";
			}
			throw new JEPFunctionException(errorMessage);
		}

		if (arguments.length > getMaxArguments()) {
			throw new JEPFunctionException("Too many arguments. For "
					+ getFunctionName() + " a maximum of " + getMaxArguments()
					+ " arguments is supported.");
		}

		DigesterConfig config = new DigesterConfig();
		config.setAlgorithm(algorithm);

		// parse salt size from arguments
		config.setSaltSize(getSaltSize(arguments));

		// parse number of iterations from arguments
		config.setIterations(getIterations(arguments));

		return apply(config, arguments);
	}

	@Override
	public FunctionDescription getFunctionDescription() {
		return new FunctionDescription(functionName + "()", algorithm,
				getHelpText(algorithm),
				FunctionDescription.UNLIMITED_NUMBER_OF_ARGUMENTS);
	}

	@Override
	public String getFunctionName() {
		return functionName;
	}

	private Integer getIterations(Object... arguments)
			throws JEPFunctionException {

		// If iterations are not defined use the default number of iterations
		if (arguments.length != getMaxArguments()) {
			return 1;
		}

		// get iterations from arguments (iterations is always the last
		// argument for the function, so first argument in the argument list as
		// it is provided in reverse order) and do some sanity checks
		Object arg2 = arguments[0];
		int numberOfIterations = 1;
		if (arg2 instanceof Number) {
			numberOfIterations = ((Number) arg2).intValue();
		} else {
			throw new JEPFunctionException(
					"Wrong input type for number of iterations argument. Only numbers are allowed.");
		}
		if (numberOfIterations < 1) {
			throw new JEPFunctionException(
					"The number of iterations has to be >= 1. Specified number of iterations: "
							+ numberOfIterations);
		}
		return numberOfIterations;
	}

	private Integer getSaltSize(Object... arguments)
			throws JEPFunctionException {

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
		Object arg1 = arguments[index];
		Integer saltSize = 8;
		if (arg1 instanceof Number) {
			saltSize = ((Number) arg1).intValue();
		} else {
			throw new JEPFunctionException(
					"Wrong input type for salt size argument. Only numbers are allowed.");
		}
		if (saltSize < 0) {
			throw new JEPFunctionException("The salt size has to be >= 0. "
					+ "Specified salt size: " + saltSize);
		}
		return saltSize;
	}

	/**
	 * Apply a custom digester function with the specified
	 * {@link DigesterConfig}.
	 */
	protected abstract T apply(DigesterConfig config, Object... arguments)
			throws JEPFunctionException;

	/**
	 * Defines the maximum number of arguments for the RapidMiner function.
	 */
	protected abstract int getMaxArguments();

	/**
	 * Defines the minimum number of arguments for the RapidMiner function.
	 */
	protected abstract int getMinArguments();

	/**
	 * @return the help text displayed when hovering over the function button
	 */
	protected abstract String getHelpText(String algorithm);

}
