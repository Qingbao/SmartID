package smartid.hig.no.services;

import smartid.hig.no.events.CardActionEvents;
import net.sourceforge.scuba.smartcards.CardTerminalListener;

public interface CardListener extends CardTerminalListener {

	void SmartIDCardInserted(CardActionEvents ce);

	void SmartIDCardRemoved(CardActionEvents ce);
}
