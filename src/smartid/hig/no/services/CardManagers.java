package smartid.hig.no.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Map;

import smartid.hig.no.events.CardActionEvents;

import net.sourceforge.scuba.smartcards.CardEvent;
import net.sourceforge.scuba.smartcards.CardManager;
import net.sourceforge.scuba.smartcards.CardService;
import net.sourceforge.scuba.smartcards.CardServiceException;
import net.sourceforge.scuba.smartcards.CardTerminalListener;

/**
 * Manages insertions and removals.
 * 
 */
public class CardManagers {
	private enum CardType {
		OTHER_CARD, PASSWD_CARD
	};

	private static final CardManagers INSTANCE = new CardManagers();

	private Map<CardService, CardType> cardTypes;

	private Map<CardService, BasicService> smartIDServices;

	private Collection<CardListener> listeners;

	private CardManagers() {
		cardTypes = new Hashtable<CardService, CardType>();
		smartIDServices = new Hashtable<CardService, BasicService>();
		listeners = new ArrayList<CardListener>();
		final CardManager cm = CardManager.getInstance();
		cm.addCardTerminalListener(new CardTerminalListener() {

			public void cardInserted(CardEvent ce) {
				notifyCardEvent(ce);
				CardService service = ce.getService();
				try {
					BasicService bService = new BasicService(service);
					bService.open(); /* Selects applet... */
					cardTypes.put(service, CardType.PASSWD_CARD);
					smartIDServices.put(service, bService);
					final CardActionEvents ces = new CardActionEvents(CardActionEvents.INSERTED,
							bService);
					notifysmartIDCardEvent(ces);
				} catch (CardServiceException cse) {
					cardTypes.put(service, CardType.OTHER_CARD);
				}
			}

			public void cardRemoved(CardEvent ce) {
				notifyCardEvent(ce);
				CardService service = ce.getService();
				CardType cardType = cardTypes.remove(service);
				if (cardType != null && cardType == CardType.PASSWD_CARD) {
					BasicService bService = smartIDServices.get(service);
					final CardActionEvents ces = new CardActionEvents(CardActionEvents.REMOVED,
							bService);
					notifysmartIDCardEvent(ces);
				}
			}
		});
	}

	public synchronized void addsmartIDServicesListener(CardListener l) {
		listeners.add(l);
	}

	public synchronized void removesmartIDServicesListener(
			CardListener l) {
		listeners.remove(l);
	}

	public static CardManagers getInstance() {
		return INSTANCE;
	}

	private void notifyCardEvent(final CardEvent ce) {
		for (final CardTerminalListener l : listeners) {
			(new Thread(new Runnable() {
				public void run() {
					switch (ce.getType()) {
					case CardEvent.INSERTED:
						l.cardInserted(ce);
						break;
					case CardEvent.REMOVED:
						l.cardRemoved(ce);
						break;
					}
				}
			})).start();
		}
	}

	private void notifysmartIDCardEvent(final CardActionEvents cae) {
		for (final CardListener l : listeners) {
			(new Thread(new Runnable() {
				public void run() {
					switch (cae.getType()) {
					case CardActionEvents.INSERTED:
						l.SmartIDCardInserted(cae);
						break;
					case CardActionEvents.REMOVED:
						l.SmartIDCardRemoved(cae);
						break;
					}
				}
			})).start();
		}
	}
}
