/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <ctype.h>

#include "iso3166.h"

#define COUNTRY_ID(A,B) \
	(((A)-'A')*('Z'-'A'+1) + ((B)-'A'))

/*
 * this map is relatively sparse but still about the same size as an (un)sorted
 * list would be since we are not directly save the map keys
 */
static const uint16_t country_codes[] = {
#define	MAP(A,B, C)		[COUNTRY_ID(A,B)] = (C)
	MAP('A','F', 4),	/* Afghanistan */
	MAP('A','L', 8),	/* Albania, People's Socialist Republic of */
	MAP('D','Z', 12),	/* Algeria, People's Democratic Republic of */
	MAP('A','S', 16),	/* American Samoa */
	MAP('A','D', 20),	/* Andorra, Principality of */
	MAP('A','O', 24),	/* Angola, Republic of */
	MAP('A','I', 660),	/* Anguilla */
	MAP('A','Q', 10),	/* Antarctica (the territory South of 60 deg S) */
	MAP('A','G', 28),	/* Antigua and Barbuda */
	MAP('A','R', 32),	/* Argentina, Argentine Republic */
	MAP('A','M', 51),	/* Armenia */
	MAP('A','W', 533),	/* Aruba */
	MAP('A','U', 36),	/* Australia, Commonwealth of */
	MAP('A','T', 40),	/* Austria, Republic of */
	MAP('A','Z', 31),	/* Azerbaijan, Republic of */
	MAP('B','S', 44),	/* Bahamas, Commonwealth of the */
	MAP('B','H', 48),	/* Bahrain, Kingdom of */
	MAP('B','D', 50),	/* Bangladesh, People's Republic of */
	MAP('B','B', 52),	/* Barbados */
	MAP('B','Y', 112),	/* Belarus */
	MAP('B','E', 56),	/* Belgium, Kingdom of */
	MAP('B','Z', 84),	/* Belize */
	MAP('B','J', 204),	/* Benin, People's Republic of */
	MAP('B','M', 60),	/* Bermuda */
	MAP('B','T', 64),	/* Bhutan, Kingdom of */
	MAP('B','O', 68),	/* Bolivia, Republic of */
	MAP('B','A', 70),	/* Bosnia and Herzegovina */
	MAP('B','W', 72),	/* Botswana, Republic of */
	MAP('B','V', 74),	/* Bouvet Island (Bouvetoya) */
	MAP('B','R', 76),	/* Brazil, Federative Republic of */
	MAP('I','O', 86),	/* British Indian Ocean Territory (Chagos Archipelago) */
	MAP('V','G', 92),	/* British Virgin Islands */
	MAP('B','N', 96),	/* Brunei Darussalam */
	MAP('B','G', 100),	/* Bulgaria, People's Republic of */
	MAP('B','F', 854),	/* Burkina Faso */
	MAP('B','I', 108),	/* Burundi, Republic of */
	MAP('K','H', 116),	/* Cambodia, Kingdom of */
	MAP('C','M', 120),	/* Cameroon, United Republic of */
	MAP('C','A', 124),	/* Canada */
	MAP('C','V', 132),	/* Cape Verde, Republic of */
	MAP('K','Y', 136),	/* Cayman Islands */
	MAP('C','F', 140),	/* Central African Republic */
	MAP('T','D', 148),	/* Chad, Republic of */
	MAP('C','L', 152),	/* Chile, Republic of */
	MAP('C','N', 156),	/* China, People's Republic of */
	MAP('C','X', 162),	/* Christmas Island */
	MAP('C','C', 166),	/* Cocos (Keeling) Islands */
	MAP('C','O', 170),	/* Colombia, Republic of */
	MAP('K','M', 174),	/* Comoros, Union of the */
	MAP('C','D', 180),	/* Congo, Democratic Republic of */
	MAP('C','G', 178),	/* Congo, People's Republic of */
	MAP('C','K', 184),	/* Cook Islands */
	MAP('C','R', 188),	/* Costa Rica, Republic of */
	MAP('C','I', 384),	/* Cote D'Ivoire, Ivory Coast, Republic of the */
	MAP('C','U', 192),	/* Cuba, Republic of */
	MAP('C','Y', 196),	/* Cyprus, Republic of */
	MAP('C','Z', 203),	/* Czech Republic */
	MAP('D','K', 208),	/* Denmark, Kingdom of */
	MAP('D','J', 262),	/* Djibouti, Republic of */
	MAP('D','M', 212),	/* Dominica, Commonwealth of */
	MAP('D','O', 214),	/* Dominican Republic */
	MAP('E','C', 218),	/* Ecuador, Republic of */
	MAP('E','G', 818),	/* Egypt, Arab Republic of */
	MAP('S','V', 222),	/* El Salvador, Republic of */
	MAP('G','Q', 226),	/* Equatorial Guinea, Republic of */
	MAP('E','R', 232),	/* Eritrea */
	MAP('E','E', 233),	/* Estonia */
	MAP('E','T', 231),	/* Ethiopia */
	MAP('F','O', 234),	/* Faeroe Islands */
	MAP('F','K', 238),	/* Falkland Islands (Malvinas) */
	MAP('F','J', 242),	/* Fiji, Republic of the Fiji Islands */
	MAP('F','I', 246),	/* Finland, Republic of */
	MAP('F','R', 250),	/* France, French Republic */
	MAP('G','F', 254),	/* French Guiana */
	MAP('P','F', 258),	/* French Polynesia */
	MAP('T','F', 260),	/* French Southern Territories */
	MAP('G','A', 266),	/* Gabon, Gabonese Republic */
	MAP('G','M', 270),	/* Gambia, Republic of the */
	MAP('G','E', 268),	/* Georgia */
	MAP('D','E', 276),	/* Germany */
	MAP('G','H', 288),	/* Ghana, Republic of */
	MAP('G','I', 292),	/* Gibraltar */
	MAP('G','R', 300),	/* Greece, Hellenic Republic */
	MAP('G','L', 304),	/* Greenland */
	MAP('G','D', 308),	/* Grenada */
	MAP('G','P', 312),	/* Guadaloupe */
	MAP('G','U', 316),	/* Guam */
	MAP('G','T', 320),	/* Guatemala, Republic of */
	MAP('G','N', 324),	/* Guinea, Revolutionary People's Rep'c of */
	MAP('G','W', 624),	/* Guinea-Bissau, Republic of */
	MAP('G','Y', 328),	/* Guyana, Republic of */
	MAP('H','T', 332),	/* Haiti, Republic of */
	MAP('H','M', 334),	/* Heard and McDonald Islands */
	MAP('V','A', 336),	/* Holy See (Vatican City State) */
	MAP('H','N', 340),	/* Honduras, Republic of */
	MAP('H','K', 344),	/* Hong Kong, Special Administrative Region of China */
	MAP('H','R', 191),	/* Hrvatska (Croatia) */
	MAP('H','U', 348),	/* Hungary, Hungarian People's Republic */
	MAP('I','S', 352),	/* Iceland, Republic of */
	MAP('I','N', 356),	/* India, Republic of */
	MAP('I','D', 360),	/* Indonesia, Republic of */
	MAP('I','R', 364),	/* Iran, Islamic Republic of */
	MAP('I','Q', 368),	/* Iraq, Republic of */
	MAP('I','E', 372),	/* Ireland */
	MAP('I','L', 376),	/* Israel, State of */
	MAP('I','T', 380),	/* Italy, Italian Republic */
	MAP('J','M', 388),	/* Jamaica */
	MAP('J','P', 392),	/* Japan */
	MAP('J','O', 400),	/* Jordan, Hashemite Kingdom of */
	MAP('K','Z', 398),	/* Kazakhstan, Republic of */
	MAP('K','E', 404),	/* Kenya, Republic of */
	MAP('K','I', 296),	/* Kiribati, Republic of */
	MAP('K','P', 408),	/* Korea, Democratic People's Republic of */
	MAP('K','R', 410),	/* Korea, Republic of */
	MAP('K','W', 414),	/* Kuwait, State of */
	MAP('K','G', 417),	/* Kyrgyz Republic */
	MAP('L','A', 418),	/* Lao People's Democratic Republic */
	MAP('L','V', 428),	/* Latvia */
	MAP('L','B', 422),	/* Lebanon, Lebanese Republic */
	MAP('L','S', 426),	/* Lesotho, Kingdom of */
	MAP('L','R', 430),	/* Liberia, Republic of */
	MAP('L','Y', 434),	/* Libyan Arab Jamahiriya */
	MAP('L','I', 438),	/* Liechtenstein, Principality of */
	MAP('L','T', 440),	/* Lithuania */
	MAP('L','U', 442),	/* Luxembourg, Grand Duchy of */
	MAP('M','O', 446),	/* Macao, Special Administrative Region of China */
	MAP('M','K', 807),	/* Macedonia, the former Yugoslav Republic of */
	MAP('M','G', 450),	/* Madagascar, Republic of */
	MAP('M','W', 454),	/* Malawi, Republic of */
	MAP('M','Y', 458),	/* Malaysia */
	MAP('M','V', 462),	/* Maldives, Republic of */
	MAP('M','L', 466),	/* Mali, Republic of */
	MAP('M','T', 470),	/* Malta, Republic of */
	MAP('M','H', 584),	/* Marshall Islands */
	MAP('M','Q', 474),	/* Martinique */
	MAP('M','R', 478),	/* Mauritania, Islamic Republic of */
	MAP('M','U', 480),	/* Mauritius */
	MAP('Y','T', 175),	/* Mayotte */
	MAP('M','X', 484),	/* Mexico, United Mexican States */
	MAP('F','M', 583),	/* Micronesia, Federated States of */
	MAP('M','D', 498),	/* Moldova, Republic of */
	MAP('M','C', 492),	/* Monaco, Principality of */
	MAP('M','N', 496),	/* Mongolia, Mongolian People's Republic */
	MAP('M','S', 500),	/* Montserrat */
	MAP('M','A', 504),	/* Morocco, Kingdom of */
	MAP('M','Z', 508),	/* Mozambique, People's Republic of */
	MAP('M','M', 104),	/* Myanmar */
	MAP('N','A', 516),	/* Namibia */
	MAP('N','R', 520),	/* Nauru, Republic of */
	MAP('N','P', 524),	/* Nepal, Kingdom of */
	MAP('A','N', 530),	/* Netherlands Antilles */
	MAP('N','L', 528),	/* Netherlands, Kingdom of the */
	MAP('N','C', 540),	/* New Caledonia */
	MAP('N','Z', 554),	/* New Zealand */
	MAP('N','I', 558),	/* Nicaragua, Republic of */
	MAP('N','E', 562),	/* Niger, Republic of the */
	MAP('N','G', 566),	/* Nigeria, Federal Republic of */
	MAP('N','U', 570),	/* Niue, Republic of */
	MAP('N','F', 574),	/* Norfolk Island */
	MAP('M','P', 580),	/* Northern Mariana Islands */
	MAP('N','O', 578),	/* Norway, Kingdom of */
	MAP('O','M', 512),	/* Oman, Sultanate of */
	MAP('P','K', 586),	/* Pakistan, Islamic Republic of */
	MAP('P','W', 585),	/* Palau */
	MAP('P','S', 275),	/* Palestinian Territory, Occupied */
	MAP('P','A', 591),	/* Panama, Republic of */
	MAP('P','G', 598),	/* Papua New Guinea */
	MAP('P','Y', 600),	/* Paraguay, Republic of */
	MAP('P','E', 604),	/* Peru, Republic of */
	MAP('P','H', 608),	/* Philippines, Republic of the */
	MAP('P','N', 612),	/* Pitcairn Island */
	MAP('P','L', 616),	/* Poland, Polish People's Republic */
	MAP('P','T', 620),	/* Portugal, Portuguese Republic */
	MAP('P','R', 630),	/* Puerto Rico */
	MAP('Q','A', 634),	/* Qatar, State of */
	MAP('R','E', 638),	/* Reunion */
	MAP('R','O', 642),	/* Romania, Socialist Republic of */
	MAP('R','U', 643),	/* Russian Federation */
	MAP('R','W', 646),	/* Rwanda, Rwandese Republic */
	MAP('S','H', 654),	/* St. Helena */
	MAP('K','N', 659),	/* St. Kitts and Nevis */
	MAP('L','C', 662),	/* St. Lucia */
	MAP('P','M', 666),	/* St. Pierre and Miquelon */
	MAP('V','C', 670),	/* St. Vincent and the Grenadines */
	MAP('W','S', 882),	/* Samoa, Independent State of */
	MAP('S','M', 674),	/* San Marino, Republic of */
	MAP('S','T', 678),	/* Sao Tome and Principe, Democratic Republic of */
	MAP('S','A', 682),	/* Saudi Arabia, Kingdom of */
	MAP('S','N', 686),	/* Senegal, Republic of */
	MAP('C','S', 891),	/* Serbia and Montenegro */
	MAP('S','C', 690),	/* Seychelles, Republic of */
	MAP('S','L', 694),	/* Sierra Leone, Republic of */
	MAP('S','G', 702),	/* Singapore, Republic of */
	MAP('S','K', 703),	/* Slovakia (Slovak Republic) */
	MAP('S','I', 705),	/* Slovenia */
	MAP('S','B', 90),	/* Solomon Islands */
	MAP('S','O', 706),	/* Somalia, Somali Republic */
	MAP('Z','A', 710),	/* South Africa, Republic of */
	MAP('G','S', 239),	/* South Georgia and the South Sandwich Islands */
	MAP('E','S', 724),	/* Spain, Spanish State */
	MAP('L','K', 144),	/* Sri Lanka, Democratic Socialist Republic of */
	MAP('S','D', 736),	/* Sudan, Democratic Republic of the */
	MAP('S','R', 740),	/* Suriname, Republic of */
	MAP('S','J', 744),	/* Svalbard & Jan Mayen Islands */
	MAP('S','Z', 748),	/* Swaziland, Kingdom of */
	MAP('S','E', 752),	/* Sweden, Kingdom of */
	MAP('C','H', 756),	/* Switzerland, Swiss Confederation */
	MAP('S','Y', 760),	/* Syrian Arab Republic */
	MAP('T','W', 158),	/* Taiwan, Province of China */
	MAP('T','J', 762),	/* Tajikistan */
	MAP('T','Z', 834),	/* Tanzania, United Republic of */
	MAP('T','H', 764),	/* Thailand, Kingdom of */
	MAP('T','L', 626),	/* Timor-Leste, Democratic Republic of */
	MAP('T','G', 768),	/* Togo, Togolese Republic */
	MAP('T','K', 772),	/* Tokelau (Tokelau Islands) */
	MAP('T','O', 776),	/* Tonga, Kingdom of */
	MAP('T','T', 780),	/* Trinidad and Tobago, Republic of */
	MAP('T','N', 788),	/* Tunisia, Republic of */
	MAP('T','R', 792),	/* Turkey, Republic of */
	MAP('T','M', 795),	/* Turkmenistan */
	MAP('T','C', 796),	/* Turks and Caicos Islands */
	MAP('T','V', 798),	/* Tuvalu */
	MAP('V','I', 850),	/* US Virgin Islands */
	MAP('U','G', 800),	/* Uganda, Republic of */
	MAP('U','A', 804),	/* Ukraine */
	MAP('A','E', 784),	/* United Arab Emirates */
	MAP('G','B', 826),	/* United Kingdom of Great Britain & N. Ireland */
	MAP('U','M', 581),	/* United States Minor Outlying Islands */
	MAP('U','S', 840),	/* United States of America */
	MAP('U','Y', 858),	/* Uruguay, Eastern Republic of */
	MAP('U','Z', 860),	/* Uzbekistan */
	MAP('V','U', 548),	/* Vanuatu */
	MAP('V','E', 862),	/* Venezuela, Bolivarian Republic of */
	MAP('V','N', 704),	/* Viet Nam, Socialist Republic of */
	MAP('W','F', 876),	/* Wallis and Futuna Islands */
	MAP('E','H', 732),	/* Western Sahara */
	MAP('Y','E', 887),	/* Yemen */
	MAP('Z','M', 894),	/* Zambia, Republic of */
	MAP('Z','W', 716)	/* Zimbabwe */
#undef	MAP
};
#define COUNTRY_CODES_MAX \
	(sizeof(country_codes)/sizeof(*country_codes) - 1)

unsigned int
iso3166_lookup_country(const char *country)
{
	unsigned int code = 0;

	if (country && isupper(country[0]) && isupper(country[1])) {
		unsigned int id = COUNTRY_ID(country[0], country[1]);
		if (id <= COUNTRY_CODES_MAX)
			/* id is in-bounds, 0 is returned for unused entries */
			code = country_codes[id];
	}

	return code;
}

int
iso3166_decode_regdomain(const char *domain,
			 unsigned int *country_code, int *outdoor)
{
	*country_code = iso3166_lookup_country(domain);
	if (!*country_code)
		return -1;

	switch (domain[2]) {
	case 'O': *outdoor = 1; break;
	case 'I': *outdoor = 0; break;
	case ' ': *outdoor = -1; break;
	default : return -1;
	}

	return domain[3] != '\0';
}

