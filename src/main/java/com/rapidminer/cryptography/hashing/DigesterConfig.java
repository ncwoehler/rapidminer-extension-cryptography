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

import org.jasypt.digest.config.SimpleDigesterConfig;

import com.rapidminer.cryptography.BCAlgorithmProvider;

import lombok.Data;


/**
 * Container class that is being used to store values used for configuring
 * digesters. We cannot use {@link SimpleDigesterConfig} as hash key as
 * {@link #equals(Object)} and {@link #hashCode()} haven't been implemented for
 * that class.
 * 
 * @author Nils Woehler
 * 
 */
@Data
class DigesterConfig {

	private String algorithm;
	private int saltSize;
	private int iterations;

	org.jasypt.digest.config.DigesterConfig toDigesterConfig() {
		SimpleDigesterConfig config = new SimpleDigesterConfig();
		config.setProvider(BCAlgorithmProvider.INSTANCE.getProvider());
		config.setIterations(getIterations());
		config.setAlgorithm(getAlgorithm());
		config.setSaltSizeBytes(getSaltSize());
		config.setPoolSize(Math.max(1, Runtime.getRuntime()
				.availableProcessors() - 1));
		return config;
	}


}
