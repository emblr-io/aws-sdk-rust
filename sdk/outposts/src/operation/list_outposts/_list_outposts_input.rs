// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListOutpostsInput {
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum page size.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Filters the results by the lifecycle status.</p>
    pub life_cycle_status_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters the results by Availability Zone (for example, <code>us-east-1a</code>).</p>
    pub availability_zone_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Filters the results by AZ ID (for example, <code>use1-az1</code>).</p>
    pub availability_zone_id_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListOutpostsInput {
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum page size.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Filters the results by the lifecycle status.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.life_cycle_status_filter.is_none()`.
    pub fn life_cycle_status_filter(&self) -> &[::std::string::String] {
        self.life_cycle_status_filter.as_deref().unwrap_or_default()
    }
    /// <p>Filters the results by Availability Zone (for example, <code>us-east-1a</code>).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zone_filter.is_none()`.
    pub fn availability_zone_filter(&self) -> &[::std::string::String] {
        self.availability_zone_filter.as_deref().unwrap_or_default()
    }
    /// <p>Filters the results by AZ ID (for example, <code>use1-az1</code>).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zone_id_filter.is_none()`.
    pub fn availability_zone_id_filter(&self) -> &[::std::string::String] {
        self.availability_zone_id_filter.as_deref().unwrap_or_default()
    }
}
impl ListOutpostsInput {
    /// Creates a new builder-style object to manufacture [`ListOutpostsInput`](crate::operation::list_outposts::ListOutpostsInput).
    pub fn builder() -> crate::operation::list_outposts::builders::ListOutpostsInputBuilder {
        crate::operation::list_outposts::builders::ListOutpostsInputBuilder::default()
    }
}

/// A builder for [`ListOutpostsInput`](crate::operation::list_outposts::ListOutpostsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListOutpostsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) life_cycle_status_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) availability_zone_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) availability_zone_id_filter: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListOutpostsInputBuilder {
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum page size.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum page size.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum page size.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Appends an item to `life_cycle_status_filter`.
    ///
    /// To override the contents of this collection use [`set_life_cycle_status_filter`](Self::set_life_cycle_status_filter).
    ///
    /// <p>Filters the results by the lifecycle status.</p>
    pub fn life_cycle_status_filter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.life_cycle_status_filter.unwrap_or_default();
        v.push(input.into());
        self.life_cycle_status_filter = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by the lifecycle status.</p>
    pub fn set_life_cycle_status_filter(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.life_cycle_status_filter = input;
        self
    }
    /// <p>Filters the results by the lifecycle status.</p>
    pub fn get_life_cycle_status_filter(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.life_cycle_status_filter
    }
    /// Appends an item to `availability_zone_filter`.
    ///
    /// To override the contents of this collection use [`set_availability_zone_filter`](Self::set_availability_zone_filter).
    ///
    /// <p>Filters the results by Availability Zone (for example, <code>us-east-1a</code>).</p>
    pub fn availability_zone_filter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zone_filter.unwrap_or_default();
        v.push(input.into());
        self.availability_zone_filter = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by Availability Zone (for example, <code>us-east-1a</code>).</p>
    pub fn set_availability_zone_filter(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zone_filter = input;
        self
    }
    /// <p>Filters the results by Availability Zone (for example, <code>us-east-1a</code>).</p>
    pub fn get_availability_zone_filter(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zone_filter
    }
    /// Appends an item to `availability_zone_id_filter`.
    ///
    /// To override the contents of this collection use [`set_availability_zone_id_filter`](Self::set_availability_zone_id_filter).
    ///
    /// <p>Filters the results by AZ ID (for example, <code>use1-az1</code>).</p>
    pub fn availability_zone_id_filter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zone_id_filter.unwrap_or_default();
        v.push(input.into());
        self.availability_zone_id_filter = ::std::option::Option::Some(v);
        self
    }
    /// <p>Filters the results by AZ ID (for example, <code>use1-az1</code>).</p>
    pub fn set_availability_zone_id_filter(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zone_id_filter = input;
        self
    }
    /// <p>Filters the results by AZ ID (for example, <code>use1-az1</code>).</p>
    pub fn get_availability_zone_id_filter(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zone_id_filter
    }
    /// Consumes the builder and constructs a [`ListOutpostsInput`](crate::operation::list_outposts::ListOutpostsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_outposts::ListOutpostsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_outposts::ListOutpostsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            life_cycle_status_filter: self.life_cycle_status_filter,
            availability_zone_filter: self.availability_zone_filter,
            availability_zone_id_filter: self.availability_zone_id_filter,
        })
    }
}
