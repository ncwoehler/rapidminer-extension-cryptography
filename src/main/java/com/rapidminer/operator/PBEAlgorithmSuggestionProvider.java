package com.rapidminer.operator;

import java.security.Provider;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.rapidminer.gui.tools.ResourceAction;
import com.rapidminer.parameter.SuggestionProvider;
import com.rapidminer.tools.ProgressListener;

public enum PBEAlgorithmSuggestionProvider implements SuggestionProvider {

	INSTANCE;

	private static final String PBE = "PBE";
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
		Set<String> algorithmNames = new HashSet<>();
		Provider provider = new BouncyCastleProvider();
		for (Service service : provider.getServices()) {
			// only add algorithms that start with PBE (password based
			// encryption) and work for Cipher and KeyGenerator..
			if (service.getAlgorithm().startsWith(PBE)) {
				try {
					Cipher.getInstance(service.getAlgorithm(), provider);
					SecretKeyFactory.getInstance(service.getAlgorithm(), provider);

					// only add algorithms with cipher and secret key
					// factories
					algorithmNames
							.add(toHumandReadable(service.getAlgorithm()));
				} catch (Throwable t) {
					// do nothing
				}
			}
		}
		List<String> sortedAlgorithmNameList = new LinkedList<String>(
				algorithmNames);
		Collections.sort(sortedAlgorithmNameList, Collections.reverseOrder());
		return new ArrayList<Object>(sortedAlgorithmNameList);
	}

	@Override
	public ResourceAction getAction() {
		return null;
	}

	public static final String toHumandReadable(String algorithmName) {
		return algorithmName.substring(7).replaceFirst("AND", " and ");
	}

	public static final String toPasswordIdentifier(String humandReadable) {
		return "PBEWITH" + humandReadable.replaceFirst(" and ", "AND");
	}

}
