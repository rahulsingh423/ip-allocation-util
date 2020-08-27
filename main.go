package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

// stores allocated IP
var AllocatedIPs []string

const (
	//assuming CIDR is given to initialize this program: ex: 192.168.1.0/24
	CIDR = "192.168.1.0/24"
)

func main() {
	fmt.Println("Test cases to allocated minimum available IP in given subnet")
	/////// Test case1: invalid format IP /////////////////////
	// ip1, err1 := AllocatedIP("192.168.1.256")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	///// Test case2: invalid format base CIDR IP  /////////////////////
	// you have to change CIDR to some invalid range
	// ip1, err1 := AllocatedIP("192.168.1.1")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	//////// Test case3: given IP is not in range of base CIDR  /////////////////
	// ip1, err1 := AllocatedIP("192.168.2.1")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	////////// test case: CIDR Network address test ///////////////////
	// ip1, err1 := AllocatedIP("192.168.1.0")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	///////// test case: CIDR Broadcast address test ///////////////////////
	// ip1, err1 := AllocatedIP("192.168.1.255")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	/////// Test Case4: IP already allocated in given subnet //////////////////
	// ip1, err1 := AllocatedIP("192.168.1.1")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	// ip2, err2 := AllocatedIP("192.168.1.2")
	// if err2 != nil {
	// 	fmt.Printf("**Error:> %v\n", err2)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip2)
	// }

	// ip3, err3 := AllocatedIP("192.168.1.2")
	// if err3 != nil {
	// 	fmt.Printf("**Error:> %v\n", err3)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip3)
	// }

	///// Testing NIL input case ///////////////////////////
	// ip1, err1 := AllocatedIP("192.168.1.1")
	// if err1 != nil {
	// 	fmt.Printf("**Error:> %v\n", err1)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip1)
	// }

	// ip2, err2 := AllocatedIP("192.168.1.2")
	// if err2 != nil {
	// 	fmt.Printf("**Error:> %v\n", err2)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip2)
	// }

	// ip3, err3 := AllocatedIP("192.168.1.5")
	// if err3 != nil {
	// 	fmt.Printf("**Error:> %v\n", err3)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip3)
	// }

	// ip3, err3 = AllocatedIP("192.168.1.4")
	// if err3 != nil {
	// 	fmt.Printf("**Error:> %v\n", err3)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip3)
	// }

	// ip3, err3 = AllocatedIP("192.168.1.6")
	// if err3 != nil {
	// 	fmt.Printf("**Error:> %v\n", err3)
	// } else {
	// 	fmt.Printf("IP allocated successfully: %s\n", ip3)
	// }

	// ip4, err4 := AllocatedIP("")
	// if err4 != nil {
	// 	fmt.Printf("**Error[NIL Input]:> %v\n", err4)
	// } else {
	// 	fmt.Printf("\n IP allocated successfully[NIL Input]: %s\n", ip4)
	// }

	////////// Test Case: CIDR Range is full for NIL input case ///////////////
	// i := 0
	// for i = 1; i <= 255; i++ {
	// 	ip, err := AllocatedIP(fmt.Sprintf("192.168.1.%d", i))
	// 	if err != nil {
	// 		fmt.Printf("**Error[]:> %v\n", err)
	// 	} else {
	// 		fmt.Printf("\n IP allocated successfully[]: %s\n", ip)
	// 	}
	// }

	// ip4, err4 := AllocatedIP("")
	// if err4 != nil {
	// 	fmt.Printf("**Error[NIL Input]:> %v\n", err4)
	// } else {
	// 	fmt.Printf("\n IP allocated successfully[NIL Input]: %s\n", ip4)
	// }

	////// Test case: Happy Case for both types of Inputs /////////////
	ip1, err1 := AllocatedIP("192.168.1.1")
	if err1 != nil {
		fmt.Printf("**Error:> %v\n", err1)
	} else {
		fmt.Printf("IP allocated successfully: %s\n", ip1)
	}

	ip2, err2 := AllocatedIP("192.168.1.2")
	if err2 != nil {
		fmt.Printf("**Error:> %v\n", err2)
	} else {
		fmt.Printf("IP allocated successfully: %s\n", ip2)
	}

	ip3, err3 := AllocatedIP("192.168.1.5")
	if err3 != nil {
		fmt.Printf("**Error:> %v\n", err3)
	} else {
		fmt.Printf(" IP allocated successfully: %s\n", ip3)
	}

	ip3, err3 = AllocatedIP("192.168.1.4")
	if err3 != nil {
		fmt.Printf("**Error:> %v\n", err3)
	} else {
		fmt.Printf(" IP allocated successfully: %s\n", ip3)
	}

	ip3, err3 = AllocatedIP("192.168.1.6")
	if err3 != nil {
		fmt.Printf("**Error:> %v\n", err3)
	} else {
		fmt.Printf(" IP allocated successfully: %s\n", ip3)
	}

	ip4, err4 := AllocatedIP("")
	if err4 != nil {
		fmt.Printf("**Error[NIL Input]:> %v\n", err4)
	} else {
		fmt.Printf("\n IP allocated successfully[NIL Input]: %s\n", ip4)
	}

}

// AllocatedIP is used to allocated next available IP for the given CIDR.
// If input IP is given then it allocate it and append to AllocatedIPs list.
// If no input IP then assign next minimum IP in range and update it to AllocatedIPs list.
// return allocated IP or error in case of any validation error or underlying error.
func AllocatedIP(ip string) (string, error) {
	//check if input IP is given or not.
	if ip != "" {
		// check if the input IP is in range or not.
		if err := validateIPRange(ip); err != nil {
			return "", err
		}

		// check if the input IP is already allocated or not.
		// searching linerally in allocated slice.
		for _, p := range AllocatedIPs {
			// if already allocated then return error to caller.
			if strings.Compare(p, ip) == 0 {
				return "", fmt.Errorf("IP %s is already allocated in CIDR %s range", ip, CIDR)
			}
		}
		// if not allocated then allocate and appending to allocated slice.
		AllocatedIPs = append(AllocatedIPs, ip)
		fmt.Printf("****AllocatedIPs>> %v", AllocatedIPs)
		return ip, nil
	} else {
		// If No input IP then assign next minimum IP in range and updated AllocatedIPs.
		minIP, err := allocateNextIPInRange()
		if err != nil {
			return "", fmt.Errorf("failed to allocate next free IP in CIDR %s range", CIDR, err)
		}

		AllocatedIPs = append(AllocatedIPs, minIP)
		fmt.Printf("****AllocatedIPs[NIL Input]>> %v", AllocatedIPs)
		return minIP, nil
	}
}

// allocateNextIPInRange finds and allocated min IP available in the given CIDR.
// returns allocated IP or underlying error if any.
func allocateNextIPInRange() (string, error) {
	/**
	Algo:
	1. Generate all HostIP for given CIDR: hostIPs (removing network address and broadcast address)
	2. Take the difference of AllocatedIPs slice with generated hostIPs: availableIPs
	3. If len(availableIPs) is zero means all IP's in given CIDR is already allocated,
	return RANGE IS FULL error
	4. Otherwise, sort the availableIPs in ascending order
	5. Allocate and return the minIP i.e. first element availableIPs[0] from availableIPs slice
	6. clear availableIPs slice
	**/

	// Generating all HostIP for given CIDR(removing network address and broadcast address)
	hostIPs, err := hostIPs(CIDR)
	if err != nil {
		return "", fmt.Errorf("failed to allocate IP: %v", err)
	}
	// Take the difference of AllocatedIPs slice with generated hostIPs
	availableIPs := difference(hostIPs, AllocatedIPs)

	// If len(availableIPs) is zero means all IP's in given CIDR is already allocated,
	// return RANGE IS FULL error
	if len(availableIPs) == 0 {
		return "", fmt.Errorf("failed to allocate IP: Range is FULL for given subnet %s", CIDR)
	}

	// sorting availableIPs (maintaining a slice of net.IP to handle both IPV4 and IPV6)
	sortedAvailableIPs := make([]net.IP, 0, len(availableIPs))
	for _, ip := range availableIPs {
		sortedAvailableIPs = append(sortedAvailableIPs, net.ParseIP(ip))
	}
	sort.Slice(sortedAvailableIPs, func(i, j int) bool {
		return bytes.Compare(sortedAvailableIPs[i], sortedAvailableIPs[j]) < 0
	})

	// return the minIP i.e. first element availableIPs[0] from availableIPs slice
	return sortedAvailableIPs[0].String(), nil
}

// validateIPRange checks if the given IP is in the range of base CIDR.
// returns error if CIDR format is wrong or wrong CIDR IP.
// returns error if given IP format is wrong or wrong IP.
// returns error if given IP is not in range of base CIDR.
// returns error if given IP is either network address or broadcast address of base CIDR.
func validateIPRange(ip string) error {
	var err error
	// parsing base CIDR.
	_, ipnet1, err := net.ParseCIDR(CIDR)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s, failed to parse: %v", CIDR, err)
	}
	// parsing given IP.
	subnet := strings.Split(CIDR, "/")[1]
	ip2, _, err := net.ParseCIDR(fmt.Sprintf("%s/%s", ip, subnet))
	if err != nil {
		return fmt.Errorf("invalid IP %s, failed to parse: %v", ip, err)
	}

	// checking if the given IP is in the range of base CIDR.
	if !ipnet1.Contains(ip2) {
		return fmt.Errorf("invalid IP as given IP %s is not in range of CIDR %s", ip, CIDR)
	}

	// checking if the given IP is the Network or Broadcast address of given base CIDR.
	if strings.Compare(ipnet1.IP.String(), ip) == 0 || IsBroadcastAddr(ipnet1, ip) {
		return fmt.Errorf("invalid IP as given IP %s is network/broadcast address of CIDR %s", ip, CIDR)
	}

	return nil
}

// IsBroadcastAddr checks if the given IPv4 is broadcast address or not.
// IsBroadcastAddr checks if the given IPv6 is multicast address or not.
// it takes network address of the subnet and IP addr to check.
func IsBroadcastAddr(n *net.IPNet, addr string) bool {
	if n.IP.To4() == nil {
		// In case of IPv6, there is no broadcast, there is multiCast.
		// need to write a check for multiCast address for IPv6.
		return false
	}
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))

	if strings.Compare(ip.String(), addr) == 0 {
		return true
	}
	return false
}

// difference returns difference of two given slices of IP address.
func difference(a, b []string) []string {
	m := make(map[string]bool)
	var diff []string
	for _, item := range b {
		m[item] = true
	}

	for _, item := range a {
		if _, ok := m[item]; !ok {
			diff = append(diff, item)
		}
	}
	return diff
}

// hostIPs generates and returns all valid IP's for a given CIDR.
// It removes Network and Broadcast IP addresses from result slice.
func hostIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// remove network address and broadcast address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, nil

	default:
		return ips[1 : len(ips)-1], nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

////////////////////////////////////////
// Not using below algo and its supporting function---just for your reference
/////////////////////////////////////////

// func allocateNextIPInRange() (string, error) {
// 	/**
// 	Algo:
// 	1. sort the AllocatedIPs slice in ascending order
// 	2. take the minimum IP from AllocatedIPs list: minIP
// 	3. check whether IP 1 less than minIP is a valid IP in given CIDR or not
// 	4. if yes the allocate that
// 	5. if no then move to next minIP in sorted AllocatedIPs slice and repeat 3 and 4 till
// 	we get an IP.
// 	6. If till last IP in AllocatedIPs we did not find any free IP then assign 1 larger than the
// 	maxIP in AllocatedIPs, check if its valid then assign and return otherwise return RANGE IS FULL
// 	error.
// 	**/

// 	// sorting AllocatedIPs (maintaining a slice of net.IP to handle both IPV4 and IPV6)
// 	sortedIPs := make([]net.IP, 0, len(AllocatedIPs))
// 	for _, ip := range AllocatedIPs {
// 		sortedIPs = append(sortedIPs, net.ParseIP(ip))
// 	}
// 	sort.Slice(sortedIPs, func(i, j int) bool {
// 		return bytes.Compare(sortedIPs[i], sortedIPs[j]) < 0
// 	})

// 	subnet := strings.Split(CIDR, "/")[1]
// 	for _, ip := range sortedIPs {
// 		fmt.Printf("***MinIP from sortedIPs: %s\n", ip)
// 		preIP, err := previousIP(fmt.Sprintf("%s/%s", ip, subnet))
// 		if err != nil {
// 			log.Printf("failed to get min IP: %v", err)
// 		}
// 		fmt.Printf("****Got PreIP %v from MinIP %v", preIP, ip)

// 		//check if preIP is Network or Broadcast address
// 		if validatePreIP(preIP) {
// 			// allocate and return
// 			AllocatedIPs = append(AllocatedIPs, preIP.String())
// 			return preIP.String(), nil
// 		}
// 		// otherwise, move to next IP

// 	}
// 	return "", nil
// }

// func validatePreIP(net.IP) bool {
// 	return false
// }

// func previousIP(currIP string) (net.IP, error) {
// 	ip, ipnet, err := net.ParseCIDR(currIP)
// 	if err != nil {
// 		return nil, fmt.Errorf("invlaid current IP %v: %v", currIP, err)
// 	}
// 	for j := len(ip) - 1; j >= 0; j-- {
// 		ip[j]--
// 		if ip[j] > 0 {
// 			break
// 		}
// 	}
// 	if !ipnet.Contains(ip) {
// 		return nil, fmt.Errorf("no previous IP to current IP %v:", currIP)
// 	}
// 	return ip, nil
// }
