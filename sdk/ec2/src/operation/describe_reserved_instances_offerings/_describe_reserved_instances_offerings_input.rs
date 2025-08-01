// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for DescribeReservedInstancesOfferings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReservedInstancesOfferingsInput {
    /// <p>The Availability Zone in which the Reserved Instance can be used.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>Include Reserved Instance Marketplace offerings in the response.</p>
    pub include_marketplace: ::std::option::Option<bool>,
    /// <p>The instance type that the reservation will cover (for example, <code>m1.small</code>). For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html">Amazon EC2 instance types</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub instance_type: ::std::option::Option<crate::types::InstanceType>,
    /// <p>The maximum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 94608000 (3 years)</p>
    pub max_duration: ::std::option::Option<i64>,
    /// <p>The maximum number of instances to filter when searching for offerings.</p>
    /// <p>Default: 20</p>
    pub max_instance_count: ::std::option::Option<i32>,
    /// <p>The minimum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 2592000 (1 month)</p>
    pub min_duration: ::std::option::Option<i64>,
    /// <p>The offering class of the Reserved Instance. Can be <code>standard</code> or <code>convertible</code>.</p>
    pub offering_class: ::std::option::Option<crate::types::OfferingClassType>,
    /// <p>The Reserved Instance product platform description. Instances that include <code>(Amazon VPC)</code> in the description are for use with Amazon VPC.</p>
    pub product_description: ::std::option::Option<crate::types::RiProductDescription>,
    /// <p>One or more Reserved Instances offering IDs.</p>
    pub reserved_instances_offering_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The ID of the Availability Zone.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub availability_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>availability-zone-id</code> - The ID of the Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>duration</code> - The duration of the Reserved Instance (for example, one year or three years), in seconds (<code>31536000</code> | <code>94608000</code>).</p></li>
    /// <li>
    /// <p><code>fixed-price</code> - The purchase price of the Reserved Instance (for example, 9800.0).</p></li>
    /// <li>
    /// <p><code>instance-type</code> - The instance type that is covered by the reservation.</p></li>
    /// <li>
    /// <p><code>marketplace</code> - Set to <code>true</code> to show only Reserved Instance Marketplace offerings. When this filter is not used, which is the default behavior, all offerings from both Amazon Web Services and the Reserved Instance Marketplace are listed.</p></li>
    /// <li>
    /// <p><code>product-description</code> - The Reserved Instance product platform description (<code>Linux/UNIX</code> | <code>Linux with SQL Server Standard</code> | <code>Linux with SQL Server Web</code> | <code>Linux with SQL Server Enterprise</code> | <code>SUSE Linux</code> | <code>Red Hat Enterprise Linux</code> | <code>Red Hat Enterprise Linux with HA</code> | <code>Windows</code> | <code>Windows with SQL Server Standard</code> | <code>Windows with SQL Server Web</code> | <code>Windows with SQL Server Enterprise</code>).</p></li>
    /// <li>
    /// <p><code>reserved-instances-offering-id</code> - The Reserved Instances offering ID.</p></li>
    /// <li>
    /// <p><code>scope</code> - The scope of the Reserved Instance (<code>Availability Zone</code> or <code>Region</code>).</p></li>
    /// <li>
    /// <p><code>usage-price</code> - The usage price of the Reserved Instance, per hour (for example, 0.84).</p></li>
    /// </ul>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    /// <p>The tenancy of the instances covered by the reservation. A Reserved Instance with a tenancy of <code>dedicated</code> is applied to instances that run in a VPC on single-tenant hardware (i.e., Dedicated Instances).</p>
    /// <p><b>Important:</b> The <code>host</code> value cannot be used with this parameter. Use the <code>default</code> or <code>dedicated</code> values only.</p>
    /// <p>Default: <code>default</code></p>
    pub instance_tenancy: ::std::option::Option<crate::types::Tenancy>,
    /// <p>The Reserved Instance offering type. If you are using tools that predate the 2011-11-01 API version, you only have access to the <code>Medium Utilization</code> Reserved Instance offering type.</p>
    pub offering_type: ::std::option::Option<crate::types::OfferingTypeValues>,
    /// <p>The token to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for the request in a single page. The remaining results of the initial request can be seen by sending another request with the returned <code>NextToken</code> value. The maximum is 100.</p>
    /// <p>Default: 100</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeReservedInstancesOfferingsInput {
    /// <p>The Availability Zone in which the Reserved Instance can be used.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>Include Reserved Instance Marketplace offerings in the response.</p>
    pub fn include_marketplace(&self) -> ::std::option::Option<bool> {
        self.include_marketplace
    }
    /// <p>The instance type that the reservation will cover (for example, <code>m1.small</code>). For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html">Amazon EC2 instance types</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&crate::types::InstanceType> {
        self.instance_type.as_ref()
    }
    /// <p>The maximum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 94608000 (3 years)</p>
    pub fn max_duration(&self) -> ::std::option::Option<i64> {
        self.max_duration
    }
    /// <p>The maximum number of instances to filter when searching for offerings.</p>
    /// <p>Default: 20</p>
    pub fn max_instance_count(&self) -> ::std::option::Option<i32> {
        self.max_instance_count
    }
    /// <p>The minimum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 2592000 (1 month)</p>
    pub fn min_duration(&self) -> ::std::option::Option<i64> {
        self.min_duration
    }
    /// <p>The offering class of the Reserved Instance. Can be <code>standard</code> or <code>convertible</code>.</p>
    pub fn offering_class(&self) -> ::std::option::Option<&crate::types::OfferingClassType> {
        self.offering_class.as_ref()
    }
    /// <p>The Reserved Instance product platform description. Instances that include <code>(Amazon VPC)</code> in the description are for use with Amazon VPC.</p>
    pub fn product_description(&self) -> ::std::option::Option<&crate::types::RiProductDescription> {
        self.product_description.as_ref()
    }
    /// <p>One or more Reserved Instances offering IDs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reserved_instances_offering_ids.is_none()`.
    pub fn reserved_instances_offering_ids(&self) -> &[::std::string::String] {
        self.reserved_instances_offering_ids.as_deref().unwrap_or_default()
    }
    /// <p>The ID of the Availability Zone.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn availability_zone_id(&self) -> ::std::option::Option<&str> {
        self.availability_zone_id.as_deref()
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>availability-zone-id</code> - The ID of the Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>duration</code> - The duration of the Reserved Instance (for example, one year or three years), in seconds (<code>31536000</code> | <code>94608000</code>).</p></li>
    /// <li>
    /// <p><code>fixed-price</code> - The purchase price of the Reserved Instance (for example, 9800.0).</p></li>
    /// <li>
    /// <p><code>instance-type</code> - The instance type that is covered by the reservation.</p></li>
    /// <li>
    /// <p><code>marketplace</code> - Set to <code>true</code> to show only Reserved Instance Marketplace offerings. When this filter is not used, which is the default behavior, all offerings from both Amazon Web Services and the Reserved Instance Marketplace are listed.</p></li>
    /// <li>
    /// <p><code>product-description</code> - The Reserved Instance product platform description (<code>Linux/UNIX</code> | <code>Linux with SQL Server Standard</code> | <code>Linux with SQL Server Web</code> | <code>Linux with SQL Server Enterprise</code> | <code>SUSE Linux</code> | <code>Red Hat Enterprise Linux</code> | <code>Red Hat Enterprise Linux with HA</code> | <code>Windows</code> | <code>Windows with SQL Server Standard</code> | <code>Windows with SQL Server Web</code> | <code>Windows with SQL Server Enterprise</code>).</p></li>
    /// <li>
    /// <p><code>reserved-instances-offering-id</code> - The Reserved Instances offering ID.</p></li>
    /// <li>
    /// <p><code>scope</code> - The scope of the Reserved Instance (<code>Availability Zone</code> or <code>Region</code>).</p></li>
    /// <li>
    /// <p><code>usage-price</code> - The usage price of the Reserved Instance, per hour (for example, 0.84).</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The tenancy of the instances covered by the reservation. A Reserved Instance with a tenancy of <code>dedicated</code> is applied to instances that run in a VPC on single-tenant hardware (i.e., Dedicated Instances).</p>
    /// <p><b>Important:</b> The <code>host</code> value cannot be used with this parameter. Use the <code>default</code> or <code>dedicated</code> values only.</p>
    /// <p>Default: <code>default</code></p>
    pub fn instance_tenancy(&self) -> ::std::option::Option<&crate::types::Tenancy> {
        self.instance_tenancy.as_ref()
    }
    /// <p>The Reserved Instance offering type. If you are using tools that predate the 2011-11-01 API version, you only have access to the <code>Medium Utilization</code> Reserved Instance offering type.</p>
    pub fn offering_type(&self) -> ::std::option::Option<&crate::types::OfferingTypeValues> {
        self.offering_type.as_ref()
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results of the initial request can be seen by sending another request with the returned <code>NextToken</code> value. The maximum is 100.</p>
    /// <p>Default: 100</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeReservedInstancesOfferingsInput {
    /// Creates a new builder-style object to manufacture [`DescribeReservedInstancesOfferingsInput`](crate::operation::describe_reserved_instances_offerings::DescribeReservedInstancesOfferingsInput).
    pub fn builder() -> crate::operation::describe_reserved_instances_offerings::builders::DescribeReservedInstancesOfferingsInputBuilder {
        crate::operation::describe_reserved_instances_offerings::builders::DescribeReservedInstancesOfferingsInputBuilder::default()
    }
}

/// A builder for [`DescribeReservedInstancesOfferingsInput`](crate::operation::describe_reserved_instances_offerings::DescribeReservedInstancesOfferingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReservedInstancesOfferingsInputBuilder {
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) include_marketplace: ::std::option::Option<bool>,
    pub(crate) instance_type: ::std::option::Option<crate::types::InstanceType>,
    pub(crate) max_duration: ::std::option::Option<i64>,
    pub(crate) max_instance_count: ::std::option::Option<i32>,
    pub(crate) min_duration: ::std::option::Option<i64>,
    pub(crate) offering_class: ::std::option::Option<crate::types::OfferingClassType>,
    pub(crate) product_description: ::std::option::Option<crate::types::RiProductDescription>,
    pub(crate) reserved_instances_offering_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) availability_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) dry_run: ::std::option::Option<bool>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
    pub(crate) instance_tenancy: ::std::option::Option<crate::types::Tenancy>,
    pub(crate) offering_type: ::std::option::Option<crate::types::OfferingTypeValues>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeReservedInstancesOfferingsInputBuilder {
    /// <p>The Availability Zone in which the Reserved Instance can be used.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone in which the Reserved Instance can be used.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone in which the Reserved Instance can be used.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>Include Reserved Instance Marketplace offerings in the response.</p>
    pub fn include_marketplace(mut self, input: bool) -> Self {
        self.include_marketplace = ::std::option::Option::Some(input);
        self
    }
    /// <p>Include Reserved Instance Marketplace offerings in the response.</p>
    pub fn set_include_marketplace(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_marketplace = input;
        self
    }
    /// <p>Include Reserved Instance Marketplace offerings in the response.</p>
    pub fn get_include_marketplace(&self) -> &::std::option::Option<bool> {
        &self.include_marketplace
    }
    /// <p>The instance type that the reservation will cover (for example, <code>m1.small</code>). For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html">Amazon EC2 instance types</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn instance_type(mut self, input: crate::types::InstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type that the reservation will cover (for example, <code>m1.small</code>). For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html">Amazon EC2 instance types</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::InstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type that the reservation will cover (for example, <code>m1.small</code>). For more information, see <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html">Amazon EC2 instance types</a> in the <i>Amazon EC2 User Guide</i>.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::InstanceType> {
        &self.instance_type
    }
    /// <p>The maximum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 94608000 (3 years)</p>
    pub fn max_duration(mut self, input: i64) -> Self {
        self.max_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 94608000 (3 years)</p>
    pub fn set_max_duration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.max_duration = input;
        self
    }
    /// <p>The maximum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 94608000 (3 years)</p>
    pub fn get_max_duration(&self) -> &::std::option::Option<i64> {
        &self.max_duration
    }
    /// <p>The maximum number of instances to filter when searching for offerings.</p>
    /// <p>Default: 20</p>
    pub fn max_instance_count(mut self, input: i32) -> Self {
        self.max_instance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of instances to filter when searching for offerings.</p>
    /// <p>Default: 20</p>
    pub fn set_max_instance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_instance_count = input;
        self
    }
    /// <p>The maximum number of instances to filter when searching for offerings.</p>
    /// <p>Default: 20</p>
    pub fn get_max_instance_count(&self) -> &::std::option::Option<i32> {
        &self.max_instance_count
    }
    /// <p>The minimum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 2592000 (1 month)</p>
    pub fn min_duration(mut self, input: i64) -> Self {
        self.min_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 2592000 (1 month)</p>
    pub fn set_min_duration(mut self, input: ::std::option::Option<i64>) -> Self {
        self.min_duration = input;
        self
    }
    /// <p>The minimum duration (in seconds) to filter when searching for offerings.</p>
    /// <p>Default: 2592000 (1 month)</p>
    pub fn get_min_duration(&self) -> &::std::option::Option<i64> {
        &self.min_duration
    }
    /// <p>The offering class of the Reserved Instance. Can be <code>standard</code> or <code>convertible</code>.</p>
    pub fn offering_class(mut self, input: crate::types::OfferingClassType) -> Self {
        self.offering_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>The offering class of the Reserved Instance. Can be <code>standard</code> or <code>convertible</code>.</p>
    pub fn set_offering_class(mut self, input: ::std::option::Option<crate::types::OfferingClassType>) -> Self {
        self.offering_class = input;
        self
    }
    /// <p>The offering class of the Reserved Instance. Can be <code>standard</code> or <code>convertible</code>.</p>
    pub fn get_offering_class(&self) -> &::std::option::Option<crate::types::OfferingClassType> {
        &self.offering_class
    }
    /// <p>The Reserved Instance product platform description. Instances that include <code>(Amazon VPC)</code> in the description are for use with Amazon VPC.</p>
    pub fn product_description(mut self, input: crate::types::RiProductDescription) -> Self {
        self.product_description = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Reserved Instance product platform description. Instances that include <code>(Amazon VPC)</code> in the description are for use with Amazon VPC.</p>
    pub fn set_product_description(mut self, input: ::std::option::Option<crate::types::RiProductDescription>) -> Self {
        self.product_description = input;
        self
    }
    /// <p>The Reserved Instance product platform description. Instances that include <code>(Amazon VPC)</code> in the description are for use with Amazon VPC.</p>
    pub fn get_product_description(&self) -> &::std::option::Option<crate::types::RiProductDescription> {
        &self.product_description
    }
    /// Appends an item to `reserved_instances_offering_ids`.
    ///
    /// To override the contents of this collection use [`set_reserved_instances_offering_ids`](Self::set_reserved_instances_offering_ids).
    ///
    /// <p>One or more Reserved Instances offering IDs.</p>
    pub fn reserved_instances_offering_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.reserved_instances_offering_ids.unwrap_or_default();
        v.push(input.into());
        self.reserved_instances_offering_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more Reserved Instances offering IDs.</p>
    pub fn set_reserved_instances_offering_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.reserved_instances_offering_ids = input;
        self
    }
    /// <p>One or more Reserved Instances offering IDs.</p>
    pub fn get_reserved_instances_offering_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.reserved_instances_offering_ids
    }
    /// <p>The ID of the Availability Zone.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn availability_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Availability Zone.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn set_availability_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone_id = input;
        self
    }
    /// <p>The ID of the Availability Zone.</p>
    /// <p>Either <code>AvailabilityZone</code> or <code>AvailabilityZoneId</code> can be specified, but not both.</p>
    pub fn get_availability_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone_id
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>availability-zone-id</code> - The ID of the Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>duration</code> - The duration of the Reserved Instance (for example, one year or three years), in seconds (<code>31536000</code> | <code>94608000</code>).</p></li>
    /// <li>
    /// <p><code>fixed-price</code> - The purchase price of the Reserved Instance (for example, 9800.0).</p></li>
    /// <li>
    /// <p><code>instance-type</code> - The instance type that is covered by the reservation.</p></li>
    /// <li>
    /// <p><code>marketplace</code> - Set to <code>true</code> to show only Reserved Instance Marketplace offerings. When this filter is not used, which is the default behavior, all offerings from both Amazon Web Services and the Reserved Instance Marketplace are listed.</p></li>
    /// <li>
    /// <p><code>product-description</code> - The Reserved Instance product platform description (<code>Linux/UNIX</code> | <code>Linux with SQL Server Standard</code> | <code>Linux with SQL Server Web</code> | <code>Linux with SQL Server Enterprise</code> | <code>SUSE Linux</code> | <code>Red Hat Enterprise Linux</code> | <code>Red Hat Enterprise Linux with HA</code> | <code>Windows</code> | <code>Windows with SQL Server Standard</code> | <code>Windows with SQL Server Web</code> | <code>Windows with SQL Server Enterprise</code>).</p></li>
    /// <li>
    /// <p><code>reserved-instances-offering-id</code> - The Reserved Instances offering ID.</p></li>
    /// <li>
    /// <p><code>scope</code> - The scope of the Reserved Instance (<code>Availability Zone</code> or <code>Region</code>).</p></li>
    /// <li>
    /// <p><code>usage-price</code> - The usage price of the Reserved Instance, per hour (for example, 0.84).</p></li>
    /// </ul>
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>availability-zone-id</code> - The ID of the Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>duration</code> - The duration of the Reserved Instance (for example, one year or three years), in seconds (<code>31536000</code> | <code>94608000</code>).</p></li>
    /// <li>
    /// <p><code>fixed-price</code> - The purchase price of the Reserved Instance (for example, 9800.0).</p></li>
    /// <li>
    /// <p><code>instance-type</code> - The instance type that is covered by the reservation.</p></li>
    /// <li>
    /// <p><code>marketplace</code> - Set to <code>true</code> to show only Reserved Instance Marketplace offerings. When this filter is not used, which is the default behavior, all offerings from both Amazon Web Services and the Reserved Instance Marketplace are listed.</p></li>
    /// <li>
    /// <p><code>product-description</code> - The Reserved Instance product platform description (<code>Linux/UNIX</code> | <code>Linux with SQL Server Standard</code> | <code>Linux with SQL Server Web</code> | <code>Linux with SQL Server Enterprise</code> | <code>SUSE Linux</code> | <code>Red Hat Enterprise Linux</code> | <code>Red Hat Enterprise Linux with HA</code> | <code>Windows</code> | <code>Windows with SQL Server Standard</code> | <code>Windows with SQL Server Web</code> | <code>Windows with SQL Server Enterprise</code>).</p></li>
    /// <li>
    /// <p><code>reserved-instances-offering-id</code> - The Reserved Instances offering ID.</p></li>
    /// <li>
    /// <p><code>scope</code> - The scope of the Reserved Instance (<code>Availability Zone</code> or <code>Region</code>).</p></li>
    /// <li>
    /// <p><code>usage-price</code> - The usage price of the Reserved Instance, per hour (for example, 0.84).</p></li>
    /// </ul>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>One or more filters.</p>
    /// <ul>
    /// <li>
    /// <p><code>availability-zone</code> - The Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>availability-zone-id</code> - The ID of the Availability Zone where the Reserved Instance can be used.</p></li>
    /// <li>
    /// <p><code>duration</code> - The duration of the Reserved Instance (for example, one year or three years), in seconds (<code>31536000</code> | <code>94608000</code>).</p></li>
    /// <li>
    /// <p><code>fixed-price</code> - The purchase price of the Reserved Instance (for example, 9800.0).</p></li>
    /// <li>
    /// <p><code>instance-type</code> - The instance type that is covered by the reservation.</p></li>
    /// <li>
    /// <p><code>marketplace</code> - Set to <code>true</code> to show only Reserved Instance Marketplace offerings. When this filter is not used, which is the default behavior, all offerings from both Amazon Web Services and the Reserved Instance Marketplace are listed.</p></li>
    /// <li>
    /// <p><code>product-description</code> - The Reserved Instance product platform description (<code>Linux/UNIX</code> | <code>Linux with SQL Server Standard</code> | <code>Linux with SQL Server Web</code> | <code>Linux with SQL Server Enterprise</code> | <code>SUSE Linux</code> | <code>Red Hat Enterprise Linux</code> | <code>Red Hat Enterprise Linux with HA</code> | <code>Windows</code> | <code>Windows with SQL Server Standard</code> | <code>Windows with SQL Server Web</code> | <code>Windows with SQL Server Enterprise</code>).</p></li>
    /// <li>
    /// <p><code>reserved-instances-offering-id</code> - The Reserved Instances offering ID.</p></li>
    /// <li>
    /// <p><code>scope</code> - The scope of the Reserved Instance (<code>Availability Zone</code> or <code>Region</code>).</p></li>
    /// <li>
    /// <p><code>usage-price</code> - The usage price of the Reserved Instance, per hour (for example, 0.84).</p></li>
    /// </ul>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// <p>The tenancy of the instances covered by the reservation. A Reserved Instance with a tenancy of <code>dedicated</code> is applied to instances that run in a VPC on single-tenant hardware (i.e., Dedicated Instances).</p>
    /// <p><b>Important:</b> The <code>host</code> value cannot be used with this parameter. Use the <code>default</code> or <code>dedicated</code> values only.</p>
    /// <p>Default: <code>default</code></p>
    pub fn instance_tenancy(mut self, input: crate::types::Tenancy) -> Self {
        self.instance_tenancy = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tenancy of the instances covered by the reservation. A Reserved Instance with a tenancy of <code>dedicated</code> is applied to instances that run in a VPC on single-tenant hardware (i.e., Dedicated Instances).</p>
    /// <p><b>Important:</b> The <code>host</code> value cannot be used with this parameter. Use the <code>default</code> or <code>dedicated</code> values only.</p>
    /// <p>Default: <code>default</code></p>
    pub fn set_instance_tenancy(mut self, input: ::std::option::Option<crate::types::Tenancy>) -> Self {
        self.instance_tenancy = input;
        self
    }
    /// <p>The tenancy of the instances covered by the reservation. A Reserved Instance with a tenancy of <code>dedicated</code> is applied to instances that run in a VPC on single-tenant hardware (i.e., Dedicated Instances).</p>
    /// <p><b>Important:</b> The <code>host</code> value cannot be used with this parameter. Use the <code>default</code> or <code>dedicated</code> values only.</p>
    /// <p>Default: <code>default</code></p>
    pub fn get_instance_tenancy(&self) -> &::std::option::Option<crate::types::Tenancy> {
        &self.instance_tenancy
    }
    /// <p>The Reserved Instance offering type. If you are using tools that predate the 2011-11-01 API version, you only have access to the <code>Medium Utilization</code> Reserved Instance offering type.</p>
    pub fn offering_type(mut self, input: crate::types::OfferingTypeValues) -> Self {
        self.offering_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Reserved Instance offering type. If you are using tools that predate the 2011-11-01 API version, you only have access to the <code>Medium Utilization</code> Reserved Instance offering type.</p>
    pub fn set_offering_type(mut self, input: ::std::option::Option<crate::types::OfferingTypeValues>) -> Self {
        self.offering_type = input;
        self
    }
    /// <p>The Reserved Instance offering type. If you are using tools that predate the 2011-11-01 API version, you only have access to the <code>Medium Utilization</code> Reserved Instance offering type.</p>
    pub fn get_offering_type(&self) -> &::std::option::Option<crate::types::OfferingTypeValues> {
        &self.offering_type
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results of the initial request can be seen by sending another request with the returned <code>NextToken</code> value. The maximum is 100.</p>
    /// <p>Default: 100</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results of the initial request can be seen by sending another request with the returned <code>NextToken</code> value. The maximum is 100.</p>
    /// <p>Default: 100</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for the request in a single page. The remaining results of the initial request can be seen by sending another request with the returned <code>NextToken</code> value. The maximum is 100.</p>
    /// <p>Default: 100</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeReservedInstancesOfferingsInput`](crate::operation::describe_reserved_instances_offerings::DescribeReservedInstancesOfferingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_reserved_instances_offerings::DescribeReservedInstancesOfferingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_reserved_instances_offerings::DescribeReservedInstancesOfferingsInput {
                availability_zone: self.availability_zone,
                include_marketplace: self.include_marketplace,
                instance_type: self.instance_type,
                max_duration: self.max_duration,
                max_instance_count: self.max_instance_count,
                min_duration: self.min_duration,
                offering_class: self.offering_class,
                product_description: self.product_description,
                reserved_instances_offering_ids: self.reserved_instances_offering_ids,
                availability_zone_id: self.availability_zone_id,
                dry_run: self.dry_run,
                filters: self.filters,
                instance_tenancy: self.instance_tenancy,
                offering_type: self.offering_type,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
