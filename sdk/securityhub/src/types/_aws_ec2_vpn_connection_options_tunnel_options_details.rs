// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The VPN tunnel options.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEc2VpnConnectionOptionsTunnelOptionsDetails {
    /// <p>The number of seconds after which a Dead Peer Detection (DPD) timeout occurs.</p>
    pub dpd_timeout_seconds: ::std::option::Option<i32>,
    /// <p>The Internet Key Exchange (IKE) versions that are permitted for the VPN tunnel.</p>
    pub ike_versions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The external IP address of the VPN tunnel.</p>
    pub outside_ip_address: ::std::option::Option<::std::string::String>,
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub phase1_dh_group_numbers: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub phase1_encryption_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub phase1_integrity_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The lifetime for phase 1 of the IKE negotiation, in seconds.</p>
    pub phase1_lifetime_seconds: ::std::option::Option<i32>,
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub phase2_dh_group_numbers: ::std::option::Option<::std::vec::Vec<i32>>,
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub phase2_encryption_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub phase2_integrity_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The lifetime for phase 2 of the IKE negotiation, in seconds.</p>
    pub phase2_lifetime_seconds: ::std::option::Option<i32>,
    /// <p>The preshared key to establish initial authentication between the virtual private gateway and the customer gateway.</p>
    pub pre_shared_key: ::std::option::Option<::std::string::String>,
    /// <p>The percentage of the rekey window, which is determined by <code>RekeyMarginTimeSeconds</code> during which the rekey time is randomly selected.</p>
    pub rekey_fuzz_percentage: ::std::option::Option<i32>,
    /// <p>The margin time, in seconds, before the phase 2 lifetime expires, during which the Amazon Web Services side of the VPN connection performs an IKE rekey.</p>
    pub rekey_margin_time_seconds: ::std::option::Option<i32>,
    /// <p>The number of packets in an IKE replay window.</p>
    pub replay_window_size: ::std::option::Option<i32>,
    /// <p>The range of inside IPv4 addresses for the tunnel.</p>
    pub tunnel_inside_cidr: ::std::option::Option<::std::string::String>,
}
impl AwsEc2VpnConnectionOptionsTunnelOptionsDetails {
    /// <p>The number of seconds after which a Dead Peer Detection (DPD) timeout occurs.</p>
    pub fn dpd_timeout_seconds(&self) -> ::std::option::Option<i32> {
        self.dpd_timeout_seconds
    }
    /// <p>The Internet Key Exchange (IKE) versions that are permitted for the VPN tunnel.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ike_versions.is_none()`.
    pub fn ike_versions(&self) -> &[::std::string::String] {
        self.ike_versions.as_deref().unwrap_or_default()
    }
    /// <p>The external IP address of the VPN tunnel.</p>
    pub fn outside_ip_address(&self) -> ::std::option::Option<&str> {
        self.outside_ip_address.as_deref()
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 1 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase1_dh_group_numbers.is_none()`.
    pub fn phase1_dh_group_numbers(&self) -> &[i32] {
        self.phase1_dh_group_numbers.as_deref().unwrap_or_default()
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase1_encryption_algorithms.is_none()`.
    pub fn phase1_encryption_algorithms(&self) -> &[::std::string::String] {
        self.phase1_encryption_algorithms.as_deref().unwrap_or_default()
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase1_integrity_algorithms.is_none()`.
    pub fn phase1_integrity_algorithms(&self) -> &[::std::string::String] {
        self.phase1_integrity_algorithms.as_deref().unwrap_or_default()
    }
    /// <p>The lifetime for phase 1 of the IKE negotiation, in seconds.</p>
    pub fn phase1_lifetime_seconds(&self) -> ::std::option::Option<i32> {
        self.phase1_lifetime_seconds
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 2 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase2_dh_group_numbers.is_none()`.
    pub fn phase2_dh_group_numbers(&self) -> &[i32] {
        self.phase2_dh_group_numbers.as_deref().unwrap_or_default()
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase2_encryption_algorithms.is_none()`.
    pub fn phase2_encryption_algorithms(&self) -> &[::std::string::String] {
        self.phase2_encryption_algorithms.as_deref().unwrap_or_default()
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phase2_integrity_algorithms.is_none()`.
    pub fn phase2_integrity_algorithms(&self) -> &[::std::string::String] {
        self.phase2_integrity_algorithms.as_deref().unwrap_or_default()
    }
    /// <p>The lifetime for phase 2 of the IKE negotiation, in seconds.</p>
    pub fn phase2_lifetime_seconds(&self) -> ::std::option::Option<i32> {
        self.phase2_lifetime_seconds
    }
    /// <p>The preshared key to establish initial authentication between the virtual private gateway and the customer gateway.</p>
    pub fn pre_shared_key(&self) -> ::std::option::Option<&str> {
        self.pre_shared_key.as_deref()
    }
    /// <p>The percentage of the rekey window, which is determined by <code>RekeyMarginTimeSeconds</code> during which the rekey time is randomly selected.</p>
    pub fn rekey_fuzz_percentage(&self) -> ::std::option::Option<i32> {
        self.rekey_fuzz_percentage
    }
    /// <p>The margin time, in seconds, before the phase 2 lifetime expires, during which the Amazon Web Services side of the VPN connection performs an IKE rekey.</p>
    pub fn rekey_margin_time_seconds(&self) -> ::std::option::Option<i32> {
        self.rekey_margin_time_seconds
    }
    /// <p>The number of packets in an IKE replay window.</p>
    pub fn replay_window_size(&self) -> ::std::option::Option<i32> {
        self.replay_window_size
    }
    /// <p>The range of inside IPv4 addresses for the tunnel.</p>
    pub fn tunnel_inside_cidr(&self) -> ::std::option::Option<&str> {
        self.tunnel_inside_cidr.as_deref()
    }
}
impl AwsEc2VpnConnectionOptionsTunnelOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsEc2VpnConnectionOptionsTunnelOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsEc2VpnConnectionOptionsTunnelOptionsDetailsBuilder {
        crate::types::builders::AwsEc2VpnConnectionOptionsTunnelOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsEc2VpnConnectionOptionsTunnelOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEc2VpnConnectionOptionsTunnelOptionsDetailsBuilder {
    pub(crate) dpd_timeout_seconds: ::std::option::Option<i32>,
    pub(crate) ike_versions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) outside_ip_address: ::std::option::Option<::std::string::String>,
    pub(crate) phase1_dh_group_numbers: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) phase1_encryption_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) phase1_integrity_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) phase1_lifetime_seconds: ::std::option::Option<i32>,
    pub(crate) phase2_dh_group_numbers: ::std::option::Option<::std::vec::Vec<i32>>,
    pub(crate) phase2_encryption_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) phase2_integrity_algorithms: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) phase2_lifetime_seconds: ::std::option::Option<i32>,
    pub(crate) pre_shared_key: ::std::option::Option<::std::string::String>,
    pub(crate) rekey_fuzz_percentage: ::std::option::Option<i32>,
    pub(crate) rekey_margin_time_seconds: ::std::option::Option<i32>,
    pub(crate) replay_window_size: ::std::option::Option<i32>,
    pub(crate) tunnel_inside_cidr: ::std::option::Option<::std::string::String>,
}
impl AwsEc2VpnConnectionOptionsTunnelOptionsDetailsBuilder {
    /// <p>The number of seconds after which a Dead Peer Detection (DPD) timeout occurs.</p>
    pub fn dpd_timeout_seconds(mut self, input: i32) -> Self {
        self.dpd_timeout_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of seconds after which a Dead Peer Detection (DPD) timeout occurs.</p>
    pub fn set_dpd_timeout_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.dpd_timeout_seconds = input;
        self
    }
    /// <p>The number of seconds after which a Dead Peer Detection (DPD) timeout occurs.</p>
    pub fn get_dpd_timeout_seconds(&self) -> &::std::option::Option<i32> {
        &self.dpd_timeout_seconds
    }
    /// Appends an item to `ike_versions`.
    ///
    /// To override the contents of this collection use [`set_ike_versions`](Self::set_ike_versions).
    ///
    /// <p>The Internet Key Exchange (IKE) versions that are permitted for the VPN tunnel.</p>
    pub fn ike_versions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ike_versions.unwrap_or_default();
        v.push(input.into());
        self.ike_versions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Internet Key Exchange (IKE) versions that are permitted for the VPN tunnel.</p>
    pub fn set_ike_versions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ike_versions = input;
        self
    }
    /// <p>The Internet Key Exchange (IKE) versions that are permitted for the VPN tunnel.</p>
    pub fn get_ike_versions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ike_versions
    }
    /// <p>The external IP address of the VPN tunnel.</p>
    pub fn outside_ip_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.outside_ip_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The external IP address of the VPN tunnel.</p>
    pub fn set_outside_ip_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.outside_ip_address = input;
        self
    }
    /// <p>The external IP address of the VPN tunnel.</p>
    pub fn get_outside_ip_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.outside_ip_address
    }
    /// Appends an item to `phase1_dh_group_numbers`.
    ///
    /// To override the contents of this collection use [`set_phase1_dh_group_numbers`](Self::set_phase1_dh_group_numbers).
    ///
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn phase1_dh_group_numbers(mut self, input: i32) -> Self {
        let mut v = self.phase1_dh_group_numbers.unwrap_or_default();
        v.push(input);
        self.phase1_dh_group_numbers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn set_phase1_dh_group_numbers(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.phase1_dh_group_numbers = input;
        self
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn get_phase1_dh_group_numbers(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.phase1_dh_group_numbers
    }
    /// Appends an item to `phase1_encryption_algorithms`.
    ///
    /// To override the contents of this collection use [`set_phase1_encryption_algorithms`](Self::set_phase1_encryption_algorithms).
    ///
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn phase1_encryption_algorithms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.phase1_encryption_algorithms.unwrap_or_default();
        v.push(input.into());
        self.phase1_encryption_algorithms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn set_phase1_encryption_algorithms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.phase1_encryption_algorithms = input;
        self
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn get_phase1_encryption_algorithms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.phase1_encryption_algorithms
    }
    /// Appends an item to `phase1_integrity_algorithms`.
    ///
    /// To override the contents of this collection use [`set_phase1_integrity_algorithms`](Self::set_phase1_integrity_algorithms).
    ///
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn phase1_integrity_algorithms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.phase1_integrity_algorithms.unwrap_or_default();
        v.push(input.into());
        self.phase1_integrity_algorithms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn set_phase1_integrity_algorithms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.phase1_integrity_algorithms = input;
        self
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 1 IKE negotiations.</p>
    pub fn get_phase1_integrity_algorithms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.phase1_integrity_algorithms
    }
    /// <p>The lifetime for phase 1 of the IKE negotiation, in seconds.</p>
    pub fn phase1_lifetime_seconds(mut self, input: i32) -> Self {
        self.phase1_lifetime_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lifetime for phase 1 of the IKE negotiation, in seconds.</p>
    pub fn set_phase1_lifetime_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.phase1_lifetime_seconds = input;
        self
    }
    /// <p>The lifetime for phase 1 of the IKE negotiation, in seconds.</p>
    pub fn get_phase1_lifetime_seconds(&self) -> &::std::option::Option<i32> {
        &self.phase1_lifetime_seconds
    }
    /// Appends an item to `phase2_dh_group_numbers`.
    ///
    /// To override the contents of this collection use [`set_phase2_dh_group_numbers`](Self::set_phase2_dh_group_numbers).
    ///
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn phase2_dh_group_numbers(mut self, input: i32) -> Self {
        let mut v = self.phase2_dh_group_numbers.unwrap_or_default();
        v.push(input);
        self.phase2_dh_group_numbers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn set_phase2_dh_group_numbers(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.phase2_dh_group_numbers = input;
        self
    }
    /// <p>The permitted Diffie-Hellman group numbers for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn get_phase2_dh_group_numbers(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.phase2_dh_group_numbers
    }
    /// Appends an item to `phase2_encryption_algorithms`.
    ///
    /// To override the contents of this collection use [`set_phase2_encryption_algorithms`](Self::set_phase2_encryption_algorithms).
    ///
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn phase2_encryption_algorithms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.phase2_encryption_algorithms.unwrap_or_default();
        v.push(input.into());
        self.phase2_encryption_algorithms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn set_phase2_encryption_algorithms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.phase2_encryption_algorithms = input;
        self
    }
    /// <p>The permitted encryption algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn get_phase2_encryption_algorithms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.phase2_encryption_algorithms
    }
    /// Appends an item to `phase2_integrity_algorithms`.
    ///
    /// To override the contents of this collection use [`set_phase2_integrity_algorithms`](Self::set_phase2_integrity_algorithms).
    ///
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn phase2_integrity_algorithms(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.phase2_integrity_algorithms.unwrap_or_default();
        v.push(input.into());
        self.phase2_integrity_algorithms = ::std::option::Option::Some(v);
        self
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn set_phase2_integrity_algorithms(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.phase2_integrity_algorithms = input;
        self
    }
    /// <p>The permitted integrity algorithms for the VPN tunnel for phase 2 IKE negotiations.</p>
    pub fn get_phase2_integrity_algorithms(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.phase2_integrity_algorithms
    }
    /// <p>The lifetime for phase 2 of the IKE negotiation, in seconds.</p>
    pub fn phase2_lifetime_seconds(mut self, input: i32) -> Self {
        self.phase2_lifetime_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The lifetime for phase 2 of the IKE negotiation, in seconds.</p>
    pub fn set_phase2_lifetime_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.phase2_lifetime_seconds = input;
        self
    }
    /// <p>The lifetime for phase 2 of the IKE negotiation, in seconds.</p>
    pub fn get_phase2_lifetime_seconds(&self) -> &::std::option::Option<i32> {
        &self.phase2_lifetime_seconds
    }
    /// <p>The preshared key to establish initial authentication between the virtual private gateway and the customer gateway.</p>
    pub fn pre_shared_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pre_shared_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The preshared key to establish initial authentication between the virtual private gateway and the customer gateway.</p>
    pub fn set_pre_shared_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pre_shared_key = input;
        self
    }
    /// <p>The preshared key to establish initial authentication between the virtual private gateway and the customer gateway.</p>
    pub fn get_pre_shared_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.pre_shared_key
    }
    /// <p>The percentage of the rekey window, which is determined by <code>RekeyMarginTimeSeconds</code> during which the rekey time is randomly selected.</p>
    pub fn rekey_fuzz_percentage(mut self, input: i32) -> Self {
        self.rekey_fuzz_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of the rekey window, which is determined by <code>RekeyMarginTimeSeconds</code> during which the rekey time is randomly selected.</p>
    pub fn set_rekey_fuzz_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rekey_fuzz_percentage = input;
        self
    }
    /// <p>The percentage of the rekey window, which is determined by <code>RekeyMarginTimeSeconds</code> during which the rekey time is randomly selected.</p>
    pub fn get_rekey_fuzz_percentage(&self) -> &::std::option::Option<i32> {
        &self.rekey_fuzz_percentage
    }
    /// <p>The margin time, in seconds, before the phase 2 lifetime expires, during which the Amazon Web Services side of the VPN connection performs an IKE rekey.</p>
    pub fn rekey_margin_time_seconds(mut self, input: i32) -> Self {
        self.rekey_margin_time_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The margin time, in seconds, before the phase 2 lifetime expires, during which the Amazon Web Services side of the VPN connection performs an IKE rekey.</p>
    pub fn set_rekey_margin_time_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rekey_margin_time_seconds = input;
        self
    }
    /// <p>The margin time, in seconds, before the phase 2 lifetime expires, during which the Amazon Web Services side of the VPN connection performs an IKE rekey.</p>
    pub fn get_rekey_margin_time_seconds(&self) -> &::std::option::Option<i32> {
        &self.rekey_margin_time_seconds
    }
    /// <p>The number of packets in an IKE replay window.</p>
    pub fn replay_window_size(mut self, input: i32) -> Self {
        self.replay_window_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of packets in an IKE replay window.</p>
    pub fn set_replay_window_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.replay_window_size = input;
        self
    }
    /// <p>The number of packets in an IKE replay window.</p>
    pub fn get_replay_window_size(&self) -> &::std::option::Option<i32> {
        &self.replay_window_size
    }
    /// <p>The range of inside IPv4 addresses for the tunnel.</p>
    pub fn tunnel_inside_cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tunnel_inside_cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The range of inside IPv4 addresses for the tunnel.</p>
    pub fn set_tunnel_inside_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tunnel_inside_cidr = input;
        self
    }
    /// <p>The range of inside IPv4 addresses for the tunnel.</p>
    pub fn get_tunnel_inside_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.tunnel_inside_cidr
    }
    /// Consumes the builder and constructs a [`AwsEc2VpnConnectionOptionsTunnelOptionsDetails`](crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails).
    pub fn build(self) -> crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails {
        crate::types::AwsEc2VpnConnectionOptionsTunnelOptionsDetails {
            dpd_timeout_seconds: self.dpd_timeout_seconds,
            ike_versions: self.ike_versions,
            outside_ip_address: self.outside_ip_address,
            phase1_dh_group_numbers: self.phase1_dh_group_numbers,
            phase1_encryption_algorithms: self.phase1_encryption_algorithms,
            phase1_integrity_algorithms: self.phase1_integrity_algorithms,
            phase1_lifetime_seconds: self.phase1_lifetime_seconds,
            phase2_dh_group_numbers: self.phase2_dh_group_numbers,
            phase2_encryption_algorithms: self.phase2_encryption_algorithms,
            phase2_integrity_algorithms: self.phase2_integrity_algorithms,
            phase2_lifetime_seconds: self.phase2_lifetime_seconds,
            pre_shared_key: self.pre_shared_key,
            rekey_fuzz_percentage: self.rekey_fuzz_percentage,
            rekey_margin_time_seconds: self.rekey_margin_time_seconds,
            replay_window_size: self.replay_window_size,
            tunnel_inside_cidr: self.tunnel_inside_cidr,
        }
    }
}
