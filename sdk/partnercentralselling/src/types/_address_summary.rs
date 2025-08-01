// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains an <code>Address</code> object's subset of fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AddressSummary {
    /// <p>Specifies the end <code>Customer</code>'s city associated with the <code>Opportunity</code>.</p>
    pub city: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the end <code>Customer</code>'s postal code associated with the <code>Opportunity</code>.</p>
    pub postal_code: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the end <code>Customer</code>'s state or region associated with the <code>Opportunity</code>.</p>
    /// <p>Valid values: <code>Alabama | Alaska | American Samoa | Arizona | Arkansas | California | Colorado | Connecticut | Delaware | Dist. of Columbia | Federated States of Micronesia | Florida | Georgia | Guam | Hawaii | Idaho | Illinois | Indiana | Iowa | Kansas | Kentucky | Louisiana | Maine | Marshall Islands | Maryland | Massachusetts | Michigan | Minnesota | Mississippi | Missouri | Montana | Nebraska | Nevada | New Hampshire | New Jersey | New Mexico | New York | North Carolina | North Dakota | Northern Mariana Islands | Ohio | Oklahoma | Oregon | Palau | Pennsylvania | Puerto Rico | Rhode Island | South Carolina | South Dakota | Tennessee | Texas | Utah | Vermont | Virginia | Virgin Islands | Washington | West Virginia | Wisconsin | Wyoming | APO/AE | AFO/FPO | FPO, AP</code></p>
    pub state_or_region: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the end <code>Customer</code>'s country associated with the <code>Opportunity</code>.</p>
    pub country_code: ::std::option::Option<crate::types::CountryCode>,
}
impl AddressSummary {
    /// <p>Specifies the end <code>Customer</code>'s city associated with the <code>Opportunity</code>.</p>
    pub fn city(&self) -> ::std::option::Option<&str> {
        self.city.as_deref()
    }
    /// <p>Specifies the end <code>Customer</code>'s postal code associated with the <code>Opportunity</code>.</p>
    pub fn postal_code(&self) -> ::std::option::Option<&str> {
        self.postal_code.as_deref()
    }
    /// <p>Specifies the end <code>Customer</code>'s state or region associated with the <code>Opportunity</code>.</p>
    /// <p>Valid values: <code>Alabama | Alaska | American Samoa | Arizona | Arkansas | California | Colorado | Connecticut | Delaware | Dist. of Columbia | Federated States of Micronesia | Florida | Georgia | Guam | Hawaii | Idaho | Illinois | Indiana | Iowa | Kansas | Kentucky | Louisiana | Maine | Marshall Islands | Maryland | Massachusetts | Michigan | Minnesota | Mississippi | Missouri | Montana | Nebraska | Nevada | New Hampshire | New Jersey | New Mexico | New York | North Carolina | North Dakota | Northern Mariana Islands | Ohio | Oklahoma | Oregon | Palau | Pennsylvania | Puerto Rico | Rhode Island | South Carolina | South Dakota | Tennessee | Texas | Utah | Vermont | Virginia | Virgin Islands | Washington | West Virginia | Wisconsin | Wyoming | APO/AE | AFO/FPO | FPO, AP</code></p>
    pub fn state_or_region(&self) -> ::std::option::Option<&str> {
        self.state_or_region.as_deref()
    }
    /// <p>Specifies the end <code>Customer</code>'s country associated with the <code>Opportunity</code>.</p>
    pub fn country_code(&self) -> ::std::option::Option<&crate::types::CountryCode> {
        self.country_code.as_ref()
    }
}
impl ::std::fmt::Debug for AddressSummary {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AddressSummary");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.field("state_or_region", &"*** Sensitive Data Redacted ***");
        formatter.field("country_code", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl AddressSummary {
    /// Creates a new builder-style object to manufacture [`AddressSummary`](crate::types::AddressSummary).
    pub fn builder() -> crate::types::builders::AddressSummaryBuilder {
        crate::types::builders::AddressSummaryBuilder::default()
    }
}

/// A builder for [`AddressSummary`](crate::types::AddressSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AddressSummaryBuilder {
    pub(crate) city: ::std::option::Option<::std::string::String>,
    pub(crate) postal_code: ::std::option::Option<::std::string::String>,
    pub(crate) state_or_region: ::std::option::Option<::std::string::String>,
    pub(crate) country_code: ::std::option::Option<crate::types::CountryCode>,
}
impl AddressSummaryBuilder {
    /// <p>Specifies the end <code>Customer</code>'s city associated with the <code>Opportunity</code>.</p>
    pub fn city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s city associated with the <code>Opportunity</code>.</p>
    pub fn set_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.city = input;
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s city associated with the <code>Opportunity</code>.</p>
    pub fn get_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.city
    }
    /// <p>Specifies the end <code>Customer</code>'s postal code associated with the <code>Opportunity</code>.</p>
    pub fn postal_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.postal_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s postal code associated with the <code>Opportunity</code>.</p>
    pub fn set_postal_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.postal_code = input;
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s postal code associated with the <code>Opportunity</code>.</p>
    pub fn get_postal_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.postal_code
    }
    /// <p>Specifies the end <code>Customer</code>'s state or region associated with the <code>Opportunity</code>.</p>
    /// <p>Valid values: <code>Alabama | Alaska | American Samoa | Arizona | Arkansas | California | Colorado | Connecticut | Delaware | Dist. of Columbia | Federated States of Micronesia | Florida | Georgia | Guam | Hawaii | Idaho | Illinois | Indiana | Iowa | Kansas | Kentucky | Louisiana | Maine | Marshall Islands | Maryland | Massachusetts | Michigan | Minnesota | Mississippi | Missouri | Montana | Nebraska | Nevada | New Hampshire | New Jersey | New Mexico | New York | North Carolina | North Dakota | Northern Mariana Islands | Ohio | Oklahoma | Oregon | Palau | Pennsylvania | Puerto Rico | Rhode Island | South Carolina | South Dakota | Tennessee | Texas | Utah | Vermont | Virginia | Virgin Islands | Washington | West Virginia | Wisconsin | Wyoming | APO/AE | AFO/FPO | FPO, AP</code></p>
    pub fn state_or_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_or_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s state or region associated with the <code>Opportunity</code>.</p>
    /// <p>Valid values: <code>Alabama | Alaska | American Samoa | Arizona | Arkansas | California | Colorado | Connecticut | Delaware | Dist. of Columbia | Federated States of Micronesia | Florida | Georgia | Guam | Hawaii | Idaho | Illinois | Indiana | Iowa | Kansas | Kentucky | Louisiana | Maine | Marshall Islands | Maryland | Massachusetts | Michigan | Minnesota | Mississippi | Missouri | Montana | Nebraska | Nevada | New Hampshire | New Jersey | New Mexico | New York | North Carolina | North Dakota | Northern Mariana Islands | Ohio | Oklahoma | Oregon | Palau | Pennsylvania | Puerto Rico | Rhode Island | South Carolina | South Dakota | Tennessee | Texas | Utah | Vermont | Virginia | Virgin Islands | Washington | West Virginia | Wisconsin | Wyoming | APO/AE | AFO/FPO | FPO, AP</code></p>
    pub fn set_state_or_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_or_region = input;
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s state or region associated with the <code>Opportunity</code>.</p>
    /// <p>Valid values: <code>Alabama | Alaska | American Samoa | Arizona | Arkansas | California | Colorado | Connecticut | Delaware | Dist. of Columbia | Federated States of Micronesia | Florida | Georgia | Guam | Hawaii | Idaho | Illinois | Indiana | Iowa | Kansas | Kentucky | Louisiana | Maine | Marshall Islands | Maryland | Massachusetts | Michigan | Minnesota | Mississippi | Missouri | Montana | Nebraska | Nevada | New Hampshire | New Jersey | New Mexico | New York | North Carolina | North Dakota | Northern Mariana Islands | Ohio | Oklahoma | Oregon | Palau | Pennsylvania | Puerto Rico | Rhode Island | South Carolina | South Dakota | Tennessee | Texas | Utah | Vermont | Virginia | Virgin Islands | Washington | West Virginia | Wisconsin | Wyoming | APO/AE | AFO/FPO | FPO, AP</code></p>
    pub fn get_state_or_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_or_region
    }
    /// <p>Specifies the end <code>Customer</code>'s country associated with the <code>Opportunity</code>.</p>
    pub fn country_code(mut self, input: crate::types::CountryCode) -> Self {
        self.country_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s country associated with the <code>Opportunity</code>.</p>
    pub fn set_country_code(mut self, input: ::std::option::Option<crate::types::CountryCode>) -> Self {
        self.country_code = input;
        self
    }
    /// <p>Specifies the end <code>Customer</code>'s country associated with the <code>Opportunity</code>.</p>
    pub fn get_country_code(&self) -> &::std::option::Option<crate::types::CountryCode> {
        &self.country_code
    }
    /// Consumes the builder and constructs a [`AddressSummary`](crate::types::AddressSummary).
    pub fn build(self) -> crate::types::AddressSummary {
        crate::types::AddressSummary {
            city: self.city,
            postal_code: self.postal_code,
            state_or_region: self.state_or_region,
            country_code: self.country_code,
        }
    }
}
impl ::std::fmt::Debug for AddressSummaryBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AddressSummaryBuilder");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.field("state_or_region", &"*** Sensitive Data Redacted ***");
        formatter.field("country_code", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
