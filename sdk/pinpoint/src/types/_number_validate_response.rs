// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a phone number.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NumberValidateResponse {
    /// <p>The carrier or service provider that the phone number is currently registered with. In some countries and regions, this value may be the carrier or service provider that the phone number was originally registered with.</p>
    pub carrier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the city where the phone number was originally registered.</p>
    pub city: ::std::option::Option<::std::string::String>,
    /// <p>The cleansed phone number, in E.164 format, for the location where the phone number was originally registered.</p>
    pub cleansed_phone_number_e164: ::std::option::Option<::std::string::String>,
    /// <p>The cleansed phone number, in the format for the location where the phone number was originally registered.</p>
    pub cleansed_phone_number_national: ::std::option::Option<::std::string::String>,
    /// <p>The name of the country or region where the phone number was originally registered.</p>
    pub country: ::std::option::Option<::std::string::String>,
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, for the country or region where the phone number was originally registered.</p>
    pub country_code_iso2: ::std::option::Option<::std::string::String>,
    /// <p>The numeric code for the country or region where the phone number was originally registered.</p>
    pub country_code_numeric: ::std::option::Option<::std::string::String>,
    /// <p>The name of the county where the phone number was originally registered.</p>
    pub county: ::std::option::Option<::std::string::String>,
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, that was sent in the request body.</p>
    pub original_country_code_iso2: ::std::option::Option<::std::string::String>,
    /// <p>The phone number that was sent in the request body.</p>
    pub original_phone_number: ::std::option::Option<::std::string::String>,
    /// <p>The description of the phone type. Valid values are: MOBILE, LANDLINE, VOIP, INVALID, PREPAID, and OTHER.</p>
    pub phone_type: ::std::option::Option<::std::string::String>,
    /// <p>The phone type, represented by an integer. Valid values are: 0 (mobile), 1 (landline), 2 (VoIP), 3 (invalid), 4 (other), and 5 (prepaid).</p>
    pub phone_type_code: ::std::option::Option<i32>,
    /// <p>The time zone for the location where the phone number was originally registered.</p>
    pub timezone: ::std::option::Option<::std::string::String>,
    /// <p>The postal or ZIP code for the location where the phone number was originally registered.</p>
    pub zip_code: ::std::option::Option<::std::string::String>,
}
impl NumberValidateResponse {
    /// <p>The carrier or service provider that the phone number is currently registered with. In some countries and regions, this value may be the carrier or service provider that the phone number was originally registered with.</p>
    pub fn carrier(&self) -> ::std::option::Option<&str> {
        self.carrier.as_deref()
    }
    /// <p>The name of the city where the phone number was originally registered.</p>
    pub fn city(&self) -> ::std::option::Option<&str> {
        self.city.as_deref()
    }
    /// <p>The cleansed phone number, in E.164 format, for the location where the phone number was originally registered.</p>
    pub fn cleansed_phone_number_e164(&self) -> ::std::option::Option<&str> {
        self.cleansed_phone_number_e164.as_deref()
    }
    /// <p>The cleansed phone number, in the format for the location where the phone number was originally registered.</p>
    pub fn cleansed_phone_number_national(&self) -> ::std::option::Option<&str> {
        self.cleansed_phone_number_national.as_deref()
    }
    /// <p>The name of the country or region where the phone number was originally registered.</p>
    pub fn country(&self) -> ::std::option::Option<&str> {
        self.country.as_deref()
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, for the country or region where the phone number was originally registered.</p>
    pub fn country_code_iso2(&self) -> ::std::option::Option<&str> {
        self.country_code_iso2.as_deref()
    }
    /// <p>The numeric code for the country or region where the phone number was originally registered.</p>
    pub fn country_code_numeric(&self) -> ::std::option::Option<&str> {
        self.country_code_numeric.as_deref()
    }
    /// <p>The name of the county where the phone number was originally registered.</p>
    pub fn county(&self) -> ::std::option::Option<&str> {
        self.county.as_deref()
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, that was sent in the request body.</p>
    pub fn original_country_code_iso2(&self) -> ::std::option::Option<&str> {
        self.original_country_code_iso2.as_deref()
    }
    /// <p>The phone number that was sent in the request body.</p>
    pub fn original_phone_number(&self) -> ::std::option::Option<&str> {
        self.original_phone_number.as_deref()
    }
    /// <p>The description of the phone type. Valid values are: MOBILE, LANDLINE, VOIP, INVALID, PREPAID, and OTHER.</p>
    pub fn phone_type(&self) -> ::std::option::Option<&str> {
        self.phone_type.as_deref()
    }
    /// <p>The phone type, represented by an integer. Valid values are: 0 (mobile), 1 (landline), 2 (VoIP), 3 (invalid), 4 (other), and 5 (prepaid).</p>
    pub fn phone_type_code(&self) -> ::std::option::Option<i32> {
        self.phone_type_code
    }
    /// <p>The time zone for the location where the phone number was originally registered.</p>
    pub fn timezone(&self) -> ::std::option::Option<&str> {
        self.timezone.as_deref()
    }
    /// <p>The postal or ZIP code for the location where the phone number was originally registered.</p>
    pub fn zip_code(&self) -> ::std::option::Option<&str> {
        self.zip_code.as_deref()
    }
}
impl NumberValidateResponse {
    /// Creates a new builder-style object to manufacture [`NumberValidateResponse`](crate::types::NumberValidateResponse).
    pub fn builder() -> crate::types::builders::NumberValidateResponseBuilder {
        crate::types::builders::NumberValidateResponseBuilder::default()
    }
}

/// A builder for [`NumberValidateResponse`](crate::types::NumberValidateResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NumberValidateResponseBuilder {
    pub(crate) carrier: ::std::option::Option<::std::string::String>,
    pub(crate) city: ::std::option::Option<::std::string::String>,
    pub(crate) cleansed_phone_number_e164: ::std::option::Option<::std::string::String>,
    pub(crate) cleansed_phone_number_national: ::std::option::Option<::std::string::String>,
    pub(crate) country: ::std::option::Option<::std::string::String>,
    pub(crate) country_code_iso2: ::std::option::Option<::std::string::String>,
    pub(crate) country_code_numeric: ::std::option::Option<::std::string::String>,
    pub(crate) county: ::std::option::Option<::std::string::String>,
    pub(crate) original_country_code_iso2: ::std::option::Option<::std::string::String>,
    pub(crate) original_phone_number: ::std::option::Option<::std::string::String>,
    pub(crate) phone_type: ::std::option::Option<::std::string::String>,
    pub(crate) phone_type_code: ::std::option::Option<i32>,
    pub(crate) timezone: ::std::option::Option<::std::string::String>,
    pub(crate) zip_code: ::std::option::Option<::std::string::String>,
}
impl NumberValidateResponseBuilder {
    /// <p>The carrier or service provider that the phone number is currently registered with. In some countries and regions, this value may be the carrier or service provider that the phone number was originally registered with.</p>
    pub fn carrier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.carrier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The carrier or service provider that the phone number is currently registered with. In some countries and regions, this value may be the carrier or service provider that the phone number was originally registered with.</p>
    pub fn set_carrier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.carrier = input;
        self
    }
    /// <p>The carrier or service provider that the phone number is currently registered with. In some countries and regions, this value may be the carrier or service provider that the phone number was originally registered with.</p>
    pub fn get_carrier(&self) -> &::std::option::Option<::std::string::String> {
        &self.carrier
    }
    /// <p>The name of the city where the phone number was originally registered.</p>
    pub fn city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the city where the phone number was originally registered.</p>
    pub fn set_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.city = input;
        self
    }
    /// <p>The name of the city where the phone number was originally registered.</p>
    pub fn get_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.city
    }
    /// <p>The cleansed phone number, in E.164 format, for the location where the phone number was originally registered.</p>
    pub fn cleansed_phone_number_e164(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cleansed_phone_number_e164 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cleansed phone number, in E.164 format, for the location where the phone number was originally registered.</p>
    pub fn set_cleansed_phone_number_e164(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cleansed_phone_number_e164 = input;
        self
    }
    /// <p>The cleansed phone number, in E.164 format, for the location where the phone number was originally registered.</p>
    pub fn get_cleansed_phone_number_e164(&self) -> &::std::option::Option<::std::string::String> {
        &self.cleansed_phone_number_e164
    }
    /// <p>The cleansed phone number, in the format for the location where the phone number was originally registered.</p>
    pub fn cleansed_phone_number_national(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cleansed_phone_number_national = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cleansed phone number, in the format for the location where the phone number was originally registered.</p>
    pub fn set_cleansed_phone_number_national(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cleansed_phone_number_national = input;
        self
    }
    /// <p>The cleansed phone number, in the format for the location where the phone number was originally registered.</p>
    pub fn get_cleansed_phone_number_national(&self) -> &::std::option::Option<::std::string::String> {
        &self.cleansed_phone_number_national
    }
    /// <p>The name of the country or region where the phone number was originally registered.</p>
    pub fn country(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the country or region where the phone number was originally registered.</p>
    pub fn set_country(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country = input;
        self
    }
    /// <p>The name of the country or region where the phone number was originally registered.</p>
    pub fn get_country(&self) -> &::std::option::Option<::std::string::String> {
        &self.country
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, for the country or region where the phone number was originally registered.</p>
    pub fn country_code_iso2(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country_code_iso2 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, for the country or region where the phone number was originally registered.</p>
    pub fn set_country_code_iso2(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country_code_iso2 = input;
        self
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, for the country or region where the phone number was originally registered.</p>
    pub fn get_country_code_iso2(&self) -> &::std::option::Option<::std::string::String> {
        &self.country_code_iso2
    }
    /// <p>The numeric code for the country or region where the phone number was originally registered.</p>
    pub fn country_code_numeric(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country_code_numeric = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The numeric code for the country or region where the phone number was originally registered.</p>
    pub fn set_country_code_numeric(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country_code_numeric = input;
        self
    }
    /// <p>The numeric code for the country or region where the phone number was originally registered.</p>
    pub fn get_country_code_numeric(&self) -> &::std::option::Option<::std::string::String> {
        &self.country_code_numeric
    }
    /// <p>The name of the county where the phone number was originally registered.</p>
    pub fn county(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.county = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the county where the phone number was originally registered.</p>
    pub fn set_county(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.county = input;
        self
    }
    /// <p>The name of the county where the phone number was originally registered.</p>
    pub fn get_county(&self) -> &::std::option::Option<::std::string::String> {
        &self.county
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, that was sent in the request body.</p>
    pub fn original_country_code_iso2(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.original_country_code_iso2 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, that was sent in the request body.</p>
    pub fn set_original_country_code_iso2(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.original_country_code_iso2 = input;
        self
    }
    /// <p>The two-character code, in ISO 3166-1 alpha-2 format, that was sent in the request body.</p>
    pub fn get_original_country_code_iso2(&self) -> &::std::option::Option<::std::string::String> {
        &self.original_country_code_iso2
    }
    /// <p>The phone number that was sent in the request body.</p>
    pub fn original_phone_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.original_phone_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The phone number that was sent in the request body.</p>
    pub fn set_original_phone_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.original_phone_number = input;
        self
    }
    /// <p>The phone number that was sent in the request body.</p>
    pub fn get_original_phone_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.original_phone_number
    }
    /// <p>The description of the phone type. Valid values are: MOBILE, LANDLINE, VOIP, INVALID, PREPAID, and OTHER.</p>
    pub fn phone_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phone_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the phone type. Valid values are: MOBILE, LANDLINE, VOIP, INVALID, PREPAID, and OTHER.</p>
    pub fn set_phone_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phone_type = input;
        self
    }
    /// <p>The description of the phone type. Valid values are: MOBILE, LANDLINE, VOIP, INVALID, PREPAID, and OTHER.</p>
    pub fn get_phone_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.phone_type
    }
    /// <p>The phone type, represented by an integer. Valid values are: 0 (mobile), 1 (landline), 2 (VoIP), 3 (invalid), 4 (other), and 5 (prepaid).</p>
    pub fn phone_type_code(mut self, input: i32) -> Self {
        self.phone_type_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The phone type, represented by an integer. Valid values are: 0 (mobile), 1 (landline), 2 (VoIP), 3 (invalid), 4 (other), and 5 (prepaid).</p>
    pub fn set_phone_type_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.phone_type_code = input;
        self
    }
    /// <p>The phone type, represented by an integer. Valid values are: 0 (mobile), 1 (landline), 2 (VoIP), 3 (invalid), 4 (other), and 5 (prepaid).</p>
    pub fn get_phone_type_code(&self) -> &::std::option::Option<i32> {
        &self.phone_type_code
    }
    /// <p>The time zone for the location where the phone number was originally registered.</p>
    pub fn timezone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timezone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time zone for the location where the phone number was originally registered.</p>
    pub fn set_timezone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timezone = input;
        self
    }
    /// <p>The time zone for the location where the phone number was originally registered.</p>
    pub fn get_timezone(&self) -> &::std::option::Option<::std::string::String> {
        &self.timezone
    }
    /// <p>The postal or ZIP code for the location where the phone number was originally registered.</p>
    pub fn zip_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.zip_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The postal or ZIP code for the location where the phone number was originally registered.</p>
    pub fn set_zip_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.zip_code = input;
        self
    }
    /// <p>The postal or ZIP code for the location where the phone number was originally registered.</p>
    pub fn get_zip_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.zip_code
    }
    /// Consumes the builder and constructs a [`NumberValidateResponse`](crate::types::NumberValidateResponse).
    pub fn build(self) -> crate::types::NumberValidateResponse {
        crate::types::NumberValidateResponse {
            carrier: self.carrier,
            city: self.city,
            cleansed_phone_number_e164: self.cleansed_phone_number_e164,
            cleansed_phone_number_national: self.cleansed_phone_number_national,
            country: self.country,
            country_code_iso2: self.country_code_iso2,
            country_code_numeric: self.country_code_numeric,
            county: self.county,
            original_country_code_iso2: self.original_country_code_iso2,
            original_phone_number: self.original_phone_number,
            phone_type: self.phone_type,
            phone_type_code: self.phone_type_code,
            timezone: self.timezone,
            zip_code: self.zip_code,
        }
    }
}
