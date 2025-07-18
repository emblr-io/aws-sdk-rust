// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct ValidateE911AddressInput {
    /// <p>The AWS account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The address street number, such as <code>200</code> or <code>2121</code>.</p>
    pub street_number: ::std::option::Option<::std::string::String>,
    /// <p>The address street information, such as <code>8th Avenue</code>.</p>
    pub street_info: ::std::option::Option<::std::string::String>,
    /// <p>The address city, such as <code>Portland</code>.</p>
    pub city: ::std::option::Option<::std::string::String>,
    /// <p>The address state, such as <code>ME</code>.</p>
    pub state: ::std::option::Option<::std::string::String>,
    /// <p>The country in the address being validated as two-letter country code in ISO 3166-1 alpha-2 format, such as <code>US</code>. For more information, see <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1 alpha-2</a> in Wikipedia.</p>
    pub country: ::std::option::Option<::std::string::String>,
    /// <p>The dress postal code, such <code>04352</code>.</p>
    pub postal_code: ::std::option::Option<::std::string::String>,
}
impl ValidateE911AddressInput {
    /// <p>The AWS account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The address street number, such as <code>200</code> or <code>2121</code>.</p>
    pub fn street_number(&self) -> ::std::option::Option<&str> {
        self.street_number.as_deref()
    }
    /// <p>The address street information, such as <code>8th Avenue</code>.</p>
    pub fn street_info(&self) -> ::std::option::Option<&str> {
        self.street_info.as_deref()
    }
    /// <p>The address city, such as <code>Portland</code>.</p>
    pub fn city(&self) -> ::std::option::Option<&str> {
        self.city.as_deref()
    }
    /// <p>The address state, such as <code>ME</code>.</p>
    pub fn state(&self) -> ::std::option::Option<&str> {
        self.state.as_deref()
    }
    /// <p>The country in the address being validated as two-letter country code in ISO 3166-1 alpha-2 format, such as <code>US</code>. For more information, see <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1 alpha-2</a> in Wikipedia.</p>
    pub fn country(&self) -> ::std::option::Option<&str> {
        self.country.as_deref()
    }
    /// <p>The dress postal code, such <code>04352</code>.</p>
    pub fn postal_code(&self) -> ::std::option::Option<&str> {
        self.postal_code.as_deref()
    }
}
impl ::std::fmt::Debug for ValidateE911AddressInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ValidateE911AddressInput");
        formatter.field("aws_account_id", &self.aws_account_id);
        formatter.field("street_number", &"*** Sensitive Data Redacted ***");
        formatter.field("street_info", &"*** Sensitive Data Redacted ***");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("state", &"*** Sensitive Data Redacted ***");
        formatter.field("country", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl ValidateE911AddressInput {
    /// Creates a new builder-style object to manufacture [`ValidateE911AddressInput`](crate::operation::validate_e911_address::ValidateE911AddressInput).
    pub fn builder() -> crate::operation::validate_e911_address::builders::ValidateE911AddressInputBuilder {
        crate::operation::validate_e911_address::builders::ValidateE911AddressInputBuilder::default()
    }
}

/// A builder for [`ValidateE911AddressInput`](crate::operation::validate_e911_address::ValidateE911AddressInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ValidateE911AddressInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) street_number: ::std::option::Option<::std::string::String>,
    pub(crate) street_info: ::std::option::Option<::std::string::String>,
    pub(crate) city: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<::std::string::String>,
    pub(crate) country: ::std::option::Option<::std::string::String>,
    pub(crate) postal_code: ::std::option::Option<::std::string::String>,
}
impl ValidateE911AddressInputBuilder {
    /// <p>The AWS account ID.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The AWS account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The AWS account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The address street number, such as <code>200</code> or <code>2121</code>.</p>
    /// This field is required.
    pub fn street_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.street_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address street number, such as <code>200</code> or <code>2121</code>.</p>
    pub fn set_street_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.street_number = input;
        self
    }
    /// <p>The address street number, such as <code>200</code> or <code>2121</code>.</p>
    pub fn get_street_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.street_number
    }
    /// <p>The address street information, such as <code>8th Avenue</code>.</p>
    /// This field is required.
    pub fn street_info(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.street_info = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address street information, such as <code>8th Avenue</code>.</p>
    pub fn set_street_info(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.street_info = input;
        self
    }
    /// <p>The address street information, such as <code>8th Avenue</code>.</p>
    pub fn get_street_info(&self) -> &::std::option::Option<::std::string::String> {
        &self.street_info
    }
    /// <p>The address city, such as <code>Portland</code>.</p>
    /// This field is required.
    pub fn city(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.city = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address city, such as <code>Portland</code>.</p>
    pub fn set_city(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.city = input;
        self
    }
    /// <p>The address city, such as <code>Portland</code>.</p>
    pub fn get_city(&self) -> &::std::option::Option<::std::string::String> {
        &self.city
    }
    /// <p>The address state, such as <code>ME</code>.</p>
    /// This field is required.
    pub fn state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address state, such as <code>ME</code>.</p>
    pub fn set_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state = input;
        self
    }
    /// <p>The address state, such as <code>ME</code>.</p>
    pub fn get_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.state
    }
    /// <p>The country in the address being validated as two-letter country code in ISO 3166-1 alpha-2 format, such as <code>US</code>. For more information, see <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1 alpha-2</a> in Wikipedia.</p>
    /// This field is required.
    pub fn country(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.country = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The country in the address being validated as two-letter country code in ISO 3166-1 alpha-2 format, such as <code>US</code>. For more information, see <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1 alpha-2</a> in Wikipedia.</p>
    pub fn set_country(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.country = input;
        self
    }
    /// <p>The country in the address being validated as two-letter country code in ISO 3166-1 alpha-2 format, such as <code>US</code>. For more information, see <a href="https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2">ISO 3166-1 alpha-2</a> in Wikipedia.</p>
    pub fn get_country(&self) -> &::std::option::Option<::std::string::String> {
        &self.country
    }
    /// <p>The dress postal code, such <code>04352</code>.</p>
    /// This field is required.
    pub fn postal_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.postal_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dress postal code, such <code>04352</code>.</p>
    pub fn set_postal_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.postal_code = input;
        self
    }
    /// <p>The dress postal code, such <code>04352</code>.</p>
    pub fn get_postal_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.postal_code
    }
    /// Consumes the builder and constructs a [`ValidateE911AddressInput`](crate::operation::validate_e911_address::ValidateE911AddressInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::validate_e911_address::ValidateE911AddressInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::validate_e911_address::ValidateE911AddressInput {
            aws_account_id: self.aws_account_id,
            street_number: self.street_number,
            street_info: self.street_info,
            city: self.city,
            state: self.state,
            country: self.country,
            postal_code: self.postal_code,
        })
    }
}
impl ::std::fmt::Debug for ValidateE911AddressInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ValidateE911AddressInputBuilder");
        formatter.field("aws_account_id", &self.aws_account_id);
        formatter.field("street_number", &"*** Sensitive Data Redacted ***");
        formatter.field("street_info", &"*** Sensitive Data Redacted ***");
        formatter.field("city", &"*** Sensitive Data Redacted ***");
        formatter.field("state", &"*** Sensitive Data Redacted ***");
        formatter.field("country", &"*** Sensitive Data Redacted ***");
        formatter.field("postal_code", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
