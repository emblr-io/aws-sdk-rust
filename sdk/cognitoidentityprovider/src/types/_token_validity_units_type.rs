// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The time units that, with <code>IdTokenValidity</code>, <code>AccessTokenValidity</code>, and <code>RefreshTokenValidity</code>, set and display the duration of ID, access, and refresh tokens for an app client. You can assign a separate token validity unit to each type of token.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TokenValidityUnitsType {
    /// <p>A time unit for the value that you set in the <code>AccessTokenValidity</code> parameter. The default <code>AccessTokenValidity</code> time unit is <code>hours</code>. <code>AccessTokenValidity</code> duration can range from five minutes to one day.</p>
    pub access_token: ::std::option::Option<crate::types::TimeUnitsType>,
    /// <p>A time unit for the value that you set in the <code>IdTokenValidity</code> parameter. The default <code>IdTokenValidity</code> time unit is <code>hours</code>. <code>IdTokenValidity</code> duration can range from five minutes to one day.</p>
    pub id_token: ::std::option::Option<crate::types::TimeUnitsType>,
    /// <p>A time unit for the value that you set in the <code>RefreshTokenValidity</code> parameter. The default <code>RefreshTokenValidity</code> time unit is <code>days</code>. <code>RefreshTokenValidity</code> duration can range from 60 minutes to 10 years.</p>
    pub refresh_token: ::std::option::Option<crate::types::TimeUnitsType>,
}
impl TokenValidityUnitsType {
    /// <p>A time unit for the value that you set in the <code>AccessTokenValidity</code> parameter. The default <code>AccessTokenValidity</code> time unit is <code>hours</code>. <code>AccessTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn access_token(&self) -> ::std::option::Option<&crate::types::TimeUnitsType> {
        self.access_token.as_ref()
    }
    /// <p>A time unit for the value that you set in the <code>IdTokenValidity</code> parameter. The default <code>IdTokenValidity</code> time unit is <code>hours</code>. <code>IdTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn id_token(&self) -> ::std::option::Option<&crate::types::TimeUnitsType> {
        self.id_token.as_ref()
    }
    /// <p>A time unit for the value that you set in the <code>RefreshTokenValidity</code> parameter. The default <code>RefreshTokenValidity</code> time unit is <code>days</code>. <code>RefreshTokenValidity</code> duration can range from 60 minutes to 10 years.</p>
    pub fn refresh_token(&self) -> ::std::option::Option<&crate::types::TimeUnitsType> {
        self.refresh_token.as_ref()
    }
}
impl TokenValidityUnitsType {
    /// Creates a new builder-style object to manufacture [`TokenValidityUnitsType`](crate::types::TokenValidityUnitsType).
    pub fn builder() -> crate::types::builders::TokenValidityUnitsTypeBuilder {
        crate::types::builders::TokenValidityUnitsTypeBuilder::default()
    }
}

/// A builder for [`TokenValidityUnitsType`](crate::types::TokenValidityUnitsType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TokenValidityUnitsTypeBuilder {
    pub(crate) access_token: ::std::option::Option<crate::types::TimeUnitsType>,
    pub(crate) id_token: ::std::option::Option<crate::types::TimeUnitsType>,
    pub(crate) refresh_token: ::std::option::Option<crate::types::TimeUnitsType>,
}
impl TokenValidityUnitsTypeBuilder {
    /// <p>A time unit for the value that you set in the <code>AccessTokenValidity</code> parameter. The default <code>AccessTokenValidity</code> time unit is <code>hours</code>. <code>AccessTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn access_token(mut self, input: crate::types::TimeUnitsType) -> Self {
        self.access_token = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time unit for the value that you set in the <code>AccessTokenValidity</code> parameter. The default <code>AccessTokenValidity</code> time unit is <code>hours</code>. <code>AccessTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn set_access_token(mut self, input: ::std::option::Option<crate::types::TimeUnitsType>) -> Self {
        self.access_token = input;
        self
    }
    /// <p>A time unit for the value that you set in the <code>AccessTokenValidity</code> parameter. The default <code>AccessTokenValidity</code> time unit is <code>hours</code>. <code>AccessTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn get_access_token(&self) -> &::std::option::Option<crate::types::TimeUnitsType> {
        &self.access_token
    }
    /// <p>A time unit for the value that you set in the <code>IdTokenValidity</code> parameter. The default <code>IdTokenValidity</code> time unit is <code>hours</code>. <code>IdTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn id_token(mut self, input: crate::types::TimeUnitsType) -> Self {
        self.id_token = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time unit for the value that you set in the <code>IdTokenValidity</code> parameter. The default <code>IdTokenValidity</code> time unit is <code>hours</code>. <code>IdTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn set_id_token(mut self, input: ::std::option::Option<crate::types::TimeUnitsType>) -> Self {
        self.id_token = input;
        self
    }
    /// <p>A time unit for the value that you set in the <code>IdTokenValidity</code> parameter. The default <code>IdTokenValidity</code> time unit is <code>hours</code>. <code>IdTokenValidity</code> duration can range from five minutes to one day.</p>
    pub fn get_id_token(&self) -> &::std::option::Option<crate::types::TimeUnitsType> {
        &self.id_token
    }
    /// <p>A time unit for the value that you set in the <code>RefreshTokenValidity</code> parameter. The default <code>RefreshTokenValidity</code> time unit is <code>days</code>. <code>RefreshTokenValidity</code> duration can range from 60 minutes to 10 years.</p>
    pub fn refresh_token(mut self, input: crate::types::TimeUnitsType) -> Self {
        self.refresh_token = ::std::option::Option::Some(input);
        self
    }
    /// <p>A time unit for the value that you set in the <code>RefreshTokenValidity</code> parameter. The default <code>RefreshTokenValidity</code> time unit is <code>days</code>. <code>RefreshTokenValidity</code> duration can range from 60 minutes to 10 years.</p>
    pub fn set_refresh_token(mut self, input: ::std::option::Option<crate::types::TimeUnitsType>) -> Self {
        self.refresh_token = input;
        self
    }
    /// <p>A time unit for the value that you set in the <code>RefreshTokenValidity</code> parameter. The default <code>RefreshTokenValidity</code> time unit is <code>days</code>. <code>RefreshTokenValidity</code> duration can range from 60 minutes to 10 years.</p>
    pub fn get_refresh_token(&self) -> &::std::option::Option<crate::types::TimeUnitsType> {
        &self.refresh_token
    }
    /// Consumes the builder and constructs a [`TokenValidityUnitsType`](crate::types::TokenValidityUnitsType).
    pub fn build(self) -> crate::types::TokenValidityUnitsType {
        crate::types::TokenValidityUnitsType {
            access_token: self.access_token,
            id_token: self.id_token,
            refresh_token: self.refresh_token,
        }
    }
}
