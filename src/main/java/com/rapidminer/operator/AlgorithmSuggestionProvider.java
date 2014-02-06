package com.rapidminer.operator;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import com.rapidminer.operator.Operator;
import com.rapidminer.parameter.SuggestionProvider;
import com.rapidminer.tools.ProgressListener;

public enum AlgorithmSuggestionProvider implements SuggestionProvider {

	INSTANCE;

	private List<Object> algorithms = null;

	@Override
	public synchronized List<Object> getSuggestions(Operator arg0,
			ProgressListener arg1) {
		if (algorithms == null) {
			algorithms = getSupportedAlgorithms();
		}
		return algorithms;
	}

	/**
	 * @return all currently installed algorithm names that can be used to
	 *         create a cipher
	 */
	private static List<Object> getSupportedAlgorithms() {
		Set<Object> algorithmNames = new HashSet<>();
		for (Provider provider : Security.getProviders()) {
			for (Service service : provider.getServices()) {
				// only add algorithms that start with PBE (password based
				// encryption) and work for Cipher and KeyGenerator..
				if (service.getAlgorithm().startsWith("PBE")) {
					try {
						Cipher.getInstance(service.getAlgorithm());
						SecretKeyFactory.getInstance(service.getAlgorithm());

						// only add algorithms with cipher and secret key
						// factories
						algorithmNames.add(service.getAlgorithm());
					} catch (Throwable t) {
						// do nothing
					}
				}
			}
		}
		return new ArrayList<>(algorithmNames);
	}

}
