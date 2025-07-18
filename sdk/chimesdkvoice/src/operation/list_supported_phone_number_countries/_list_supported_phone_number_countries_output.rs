// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSupportedPhoneNumberCountriesOutput {
    /// <p>The supported phone number countries.</p>
    pub phone_number_countries: ::std::option::Option<::std::vec::Vec<crate::types::PhoneNumberCountry>>,
    _request_id: Option<String>,
}
impl ListSupportedPhoneNumberCountriesOutput {
    /// <p>The supported phone number countries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.phone_number_countries.is_none()`.
    pub fn phone_number_countries(&self) -> &[crate::types::PhoneNumberCountry] {
        self.phone_number_countries.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListSupportedPhoneNumberCountriesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSupportedPhoneNumberCountriesOutput {
    /// Creates a new builder-style object to manufacture [`ListSupportedPhoneNumberCountriesOutput`](crate::operation::list_supported_phone_number_countries::ListSupportedPhoneNumberCountriesOutput).
    pub fn builder() -> crate::operation::list_supported_phone_number_countries::builders::ListSupportedPhoneNumberCountriesOutputBuilder {
        crate::operation::list_supported_phone_number_countries::builders::ListSupportedPhoneNumberCountriesOutputBuilder::default()
    }
}

/// A builder for [`ListSupportedPhoneNumberCountriesOutput`](crate::operation::list_supported_phone_number_countries::ListSupportedPhoneNumberCountriesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSupportedPhoneNumberCountriesOutputBuilder {
    pub(crate) phone_number_countries: ::std::option::Option<::std::vec::Vec<crate::types::PhoneNumberCountry>>,
    _request_id: Option<String>,
}
impl ListSupportedPhoneNumberCountriesOutputBuilder {
    /// Appends an item to `phone_number_countries`.
    ///
    /// To override the contents of this collection use [`set_phone_number_countries`](Self::set_phone_number_countries).
    ///
    /// <p>The supported phone number countries.</p>
    pub fn phone_number_countries(mut self, input: crate::types::PhoneNumberCountry) -> Self {
        let mut v = self.phone_number_countries.unwrap_or_default();
        v.push(input);
        self.phone_number_countries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The supported phone number countries.</p>
    pub fn set_phone_number_countries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PhoneNumberCountry>>) -> Self {
        self.phone_number_countries = input;
        self
    }
    /// <p>The supported phone number countries.</p>
    pub fn get_phone_number_countries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PhoneNumberCountry>> {
        &self.phone_number_countries
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListSupportedPhoneNumberCountriesOutput`](crate::operation::list_supported_phone_number_countries::ListSupportedPhoneNumberCountriesOutput).
    pub fn build(self) -> crate::operation::list_supported_phone_number_countries::ListSupportedPhoneNumberCountriesOutput {
        crate::operation::list_supported_phone_number_countries::ListSupportedPhoneNumberCountriesOutput {
            phone_number_countries: self.phone_number_countries,
            _request_id: self._request_id,
        }
    }
}
