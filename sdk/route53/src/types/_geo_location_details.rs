// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains the codes and full continent, country, and subdivision names for the specified <code>geolocation</code> code.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GeoLocationDetails {
    /// <p>The two-letter code for the continent.</p>
    pub continent_code: ::std::option::Option<::std::string::String>,
    /// <p>The full name of the continent.</p>
    pub continent_name: ::std::option::Option<::std::string::String>,
    /// <p>The two-letter code for the country.</p>
    pub country_code: ::std::option::Option<::std::string::String>,
    /// <p>The name of the country.</p>
    pub country_name: ::std::option::Option<::std::string::String>,
    /// <p>The code for the subdivision, such as a particular state within the United States. For a list of US state abbreviations, see <a href="https://pe.usps.com/text/pub28/28apb.htm">Appendix B: Two–Letter State and Possession Abbreviations</a> on the United States Postal Service website. For a list of all supported subdivision codes, use the <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html">ListGeoLocations</a> API.</p>
    pub subdivision_code: ::std::option::Option<::std::string::String>,
    /// <p>The full name of the subdivision. Route 53 currently supports only states in the United States.</p>
    pub subdivision_name: ::std::option::Option<::std::string::String>,
}
impl GeoLocationDetails {
    /// <p>The two-letter code for the continent.</p>
    pub fn continent_code(&self) -> ::std::option::Option<&str> {
        self.continent_code.as_deref()
    }
    /// <p>The full name of the continent.</p>
    pub fn continent_name(&self) -> ::std::option::Option<&str> {
        self.continent_name.as_deref()
    }
    /// <p>The two-letter code for the country.</p>
    pub fn country_code(&self) -> ::std::option::Option<&str> {
        self.country_code.as_deref()
    }
    /// <p>The name of the country.</p>
    pub fn country_name(&self) -> ::std::option::Option<&str> {
        self.country_name.as_deref()
    }
    /// <p>The code for the subdivision, such as a particular state within the United States. For a list of US state abbreviations, see <a href="https://pe.usps.com/text/pub28/28apb.htm">Appendix B: Two–Letter State and Possession Abbreviations</a> on the United States Postal Service website. For a list of all supported subdivision codes, use the <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html">ListGeoLocations</a> API.</p>
    pub fn subdivision_code(&self) -> ::std::option::Option<&str> {
        self.subdivision_code.as_deref()
    }
    /// <p>The full name of the subdivision. Route 53 currently supports only states in the United States.</p>
    pub fn subdivision_name(&self) -> ::std::option::Option<&str> {
        self.subdivision_name.as_deref()
    }
}
impl GeoLocationDetails {
    /// Creates a new builder-style object to manufacture [`GeoLocationDetails`](crate::types::GeoLocationDetails).
    pub fn builder() -> crate::types::builders::GeoLocationDetailsBuilder {
        crate::types::builders::GeoLocationDetailsBuilder::default()
    }
}

/// A builder for [`GeoLocationDetails`](crate::types::GeoLocationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GeoLocationDetailsBuilder {
    pub(crate) continent_code: ::std::option::Option<::std::string::String>,
    pub(crate) continent_name: ::std::option::Option<::std::string::String>,
    pub(crate) country_code: ::std::option::Option<::std::string::String>,
    pub(crate) country_name: ::std::option::Option<::std::string::String>,
    pub(crate) subdivision_code: ::std::option::Option<::std::string::String>,
    pub(crate) subdivision_name: ::std::option::Option<::std::string::String>,
}
impl GeoLocationDetailsBuilder {
    /// <p>The two-letter code for the continent.</p>
    pub fn continent_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continent_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The two-letter code for the continent.</p>
    pub fn set_continent_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continent_code = input;
        self
    }
    /// <p>The two-letter code for the continent.</p>
    pub fn get_continent_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.continent_code
    }
    /// <p>The full name of the continent.</p>
    pub fn continent_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.continent_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full name of the continent.</p>
    pub fn set_continent_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.continent_name = input;
        self
    }
    /// <p>The full name of the continent.</p>
    pub fn get_continent_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.continent_name
    }
    /// <p>The two-letter code for the country.</p>
    pub fn country_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The two-letter code for the country.</p>
    pub fn set_country_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country_code = input;
        self
    }
    /// <p>The two-letter code for the country.</p>
    pub fn get_country_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.country_code
    }
    /// <p>The name of the country.</p>
    pub fn country_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the country.</p>
    pub fn set_country_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country_name = input;
        self
    }
    /// <p>The name of the country.</p>
    pub fn get_country_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.country_name
    }
    /// <p>The code for the subdivision, such as a particular state within the United States. For a list of US state abbreviations, see <a href="https://pe.usps.com/text/pub28/28apb.htm">Appendix B: Two–Letter State and Possession Abbreviations</a> on the United States Postal Service website. For a list of all supported subdivision codes, use the <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html">ListGeoLocations</a> API.</p>
    pub fn subdivision_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdivision_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The code for the subdivision, such as a particular state within the United States. For a list of US state abbreviations, see <a href="https://pe.usps.com/text/pub28/28apb.htm">Appendix B: Two–Letter State and Possession Abbreviations</a> on the United States Postal Service website. For a list of all supported subdivision codes, use the <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html">ListGeoLocations</a> API.</p>
    pub fn set_subdivision_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdivision_code = input;
        self
    }
    /// <p>The code for the subdivision, such as a particular state within the United States. For a list of US state abbreviations, see <a href="https://pe.usps.com/text/pub28/28apb.htm">Appendix B: Two–Letter State and Possession Abbreviations</a> on the United States Postal Service website. For a list of all supported subdivision codes, use the <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListGeoLocations.html">ListGeoLocations</a> API.</p>
    pub fn get_subdivision_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdivision_code
    }
    /// <p>The full name of the subdivision. Route 53 currently supports only states in the United States.</p>
    pub fn subdivision_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdivision_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full name of the subdivision. Route 53 currently supports only states in the United States.</p>
    pub fn set_subdivision_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdivision_name = input;
        self
    }
    /// <p>The full name of the subdivision. Route 53 currently supports only states in the United States.</p>
    pub fn get_subdivision_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdivision_name
    }
    /// Consumes the builder and constructs a [`GeoLocationDetails`](crate::types::GeoLocationDetails).
    pub fn build(self) -> crate::types::GeoLocationDetails {
        crate::types::GeoLocationDetails {
            continent_code: self.continent_code,
            continent_name: self.continent_name,
            country_code: self.country_code,
            country_name: self.country_name,
            subdivision_code: self.subdivision_code,
            subdivision_name: self.subdivision_name,
        }
    }
}
