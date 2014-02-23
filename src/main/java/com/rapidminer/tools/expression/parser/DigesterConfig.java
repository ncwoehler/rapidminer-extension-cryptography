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

import org.jasypt.digest.config.SimpleDigesterConfig;

import com.rapidminer.BCProvider;

/**
 * Container class that is being used to store values used for configuring
 * digesters. We cannot use {@link SimpleDigesterConfig} as hash key as
 * {@link #equals(Object)} and {@link #hashCode()} haven't been implemented for
 * that class.
 * 
 * @author Nils Woehler
 * 
 */
class DigesterConfig {

	private String algorithm;
	private int saltSize;
	private int iterations;

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

	public void setSaltSize(int saltSize) {
		this.saltSize = saltSize;
	}

	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	protected int getIterations() {
		return iterations;
	}

	protected String getAlgorithm() {
		return algorithm;
	}

	protected int getSaltSize() {
		return saltSize;
	}

	public org.jasypt.digest.config.DigesterConfig toDigesterConfig() {
		SimpleDigesterConfig config = new SimpleDigesterConfig();
		config.setProvider(BCProvider.INSTANCE.get());
		config.setIterations(getIterations());
		config.setAlgorithm(getAlgorithm());
		config.setSaltSizeBytes(getSaltSize());
		config.setPoolSize(Math.max(1, Runtime.getRuntime()
				.availableProcessors() - 1));
		return config;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((algorithm == null) ? 0 : algorithm.hashCode());
		result = prime * result + iterations;
		result = prime * result + saltSize;
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		DigesterConfig other = (DigesterConfig) obj;
		if (algorithm == null) {
			if (other.algorithm != null)
				return false;
		} else if (!algorithm.equals(other.algorithm))
			return false;
		if (iterations != other.iterations)
			return false;
		if (saltSize != other.saltSize)
			return false;
		return true;
	}

}
