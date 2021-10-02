package hu.marazmarci.utils.ip;

import com.github.maltalex.ineter.base.IPAddress;
import com.github.maltalex.ineter.base.IPv4Address;
import com.github.maltalex.ineter.base.IPv6Address;
import com.github.maltalex.ineter.range.*;

public class IPFilter {

    public static IPFilter create(String pattern) {
        Throwable problem;
        try {
            if (pattern.startsWith("include ")) {
                pattern = pattern.substring("include ".length());
                return new IPFilter(pattern, true);
            } else if (pattern.startsWith("exclude ")) {
                pattern = pattern.substring("exclude ".length());
                return new IPFilter(pattern, false);
            }
            throw new IllegalArgumentException("IP filter rules should start with the prefix \"include\" or \"exclude\"!");
        } catch (Throwable t) {
            problem = t;
        }
        throw new IllegalArgumentException("can't parse trustedIPFilters entry: " + pattern, problem);
    }

    private final IPRangeFilter ipRangeFilter;
    private final boolean include;

    private IPFilter(String pattern, boolean include) {
        this.ipRangeFilter = new IPRangeFilter(pattern);
        this.include = include;
    }

    public Boolean match(String ip) {
        return ipRangeFilter.match(ip) ? include : null;
    }

    public static class IPRangeFilter {

        private IPRange<?, ?> ipRange;
        private boolean isIPv4;

        private IPRangeFilter(String pattern) {
            boolean colon = pattern.contains(":");
            boolean slash = pattern.contains("/");
            boolean dash = pattern.contains("-");
            boolean dot = pattern.contains(".");
            if (dot & !colon) {
                // IPv4
                isIPv4 = true;
                if (slash & !dash) {
                    // subnet
                    ipRange = IPv4Subnet.of(pattern);
                } else if (!slash) {
                    // range or address
                    ipRange = IPv4Range.parse(pattern);
                }
            } else if (colon & !dot) {
                // IPv6
                isIPv4 = false;
                if (slash & !dash) {
                    // subnet
                    ipRange = IPv6Subnet.of(pattern);
                } else if (!slash) {
                    // range or address
                    ipRange = IPv6Range.parse(pattern);
                }
            }
            if (ipRange == null)
                throw new IllegalArgumentException("can't parse IP filter: " + pattern);
        }

        private boolean matchIPv4(IPv4Address ip4) {
            return isIPv4 && ((IPv4Range) ipRange).contains(ip4);
        }

        private boolean matchIPv6(IPv6Address ip6) {
            return !isIPv4 && ((IPv6Range) ipRange).contains(ip6);
        }

        public boolean match(String ip) {
            IPAddress ipAddress = IPAddress.of(ip);
            if (ipAddress instanceof IPv4Address) {
                return matchIPv4((IPv4Address) ipAddress);
            } else if (ipAddress instanceof IPv6Address) {
                return matchIPv6((IPv6Address) ipAddress);
            }
            return false;
        }

    }

}
