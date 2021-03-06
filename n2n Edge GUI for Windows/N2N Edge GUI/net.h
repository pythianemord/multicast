/*
  N2N Edge GUI - GUI Configuration utility for n2n edge
  Copyright (C) 2010  Ryan M. Dorn
  https://sourceforge.net/projects/n2nedgegui/
  $Id: net.h 2 2010-03-25 23:47:47Z Ryand833 $

  This file is part of N2N Edge GUI.

  N2N Edge GUI is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  N2N Edge GUI is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with N2N Edge GUI.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _H_NET
#define _H_NET

void get_mac_address(WCHAR* mac_address, WCHAR* guid);
void get_addresses(WCHAR* ip_address, WCHAR* mac_address);
bool validate_ipv4_address(WCHAR* ip_address);
bool validate_mac_address(WCHAR* mac_address);
bool validate_number_range(WCHAR* num, int min, int max);

#endif