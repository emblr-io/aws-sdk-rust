// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the operator to use in a property-based condition that filters the results of a query for information about S3 buckets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BucketCriteriaAdditionalProperties {
    /// <p>The value for the property matches (equals) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub eq: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The value for the property is greater than the specified value.</p>
    pub gt: ::std::option::Option<i64>,
    /// <p>The value for the property is greater than or equal to the specified value.</p>
    pub gte: ::std::option::Option<i64>,
    /// <p>The value for the property is less than the specified value.</p>
    pub lt: ::std::option::Option<i64>,
    /// <p>The value for the property is less than or equal to the specified value.</p>
    pub lte: ::std::option::Option<i64>,
    /// <p>The value for the property doesn't match (doesn't equal) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub neq: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The name of the bucket begins with the specified value.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
}
impl BucketCriteriaAdditionalProperties {
    /// <p>The value for the property matches (equals) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.eq.is_none()`.
    pub fn eq(&self) -> &[::std::string::String] {
        self.eq.as_deref().unwrap_or_default()
    }
    /// <p>The value for the property is greater than the specified value.</p>
    pub fn gt(&self) -> ::std::option::Option<i64> {
        self.gt
    }
    /// <p>The value for the property is greater than or equal to the specified value.</p>
    pub fn gte(&self) -> ::std::option::Option<i64> {
        self.gte
    }
    /// <p>The value for the property is less than the specified value.</p>
    pub fn lt(&self) -> ::std::option::Option<i64> {
        self.lt
    }
    /// <p>The value for the property is less than or equal to the specified value.</p>
    pub fn lte(&self) -> ::std::option::Option<i64> {
        self.lte
    }
    /// <p>The value for the property doesn't match (doesn't equal) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.neq.is_none()`.
    pub fn neq(&self) -> &[::std::string::String] {
        self.neq.as_deref().unwrap_or_default()
    }
    /// <p>The name of the bucket begins with the specified value.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
}
impl BucketCriteriaAdditionalProperties {
    /// Creates a new builder-style object to manufacture [`BucketCriteriaAdditionalProperties`](crate::types::BucketCriteriaAdditionalProperties).
    pub fn builder() -> crate::types::builders::BucketCriteriaAdditionalPropertiesBuilder {
        crate::types::builders::BucketCriteriaAdditionalPropertiesBuilder::default()
    }
}

/// A builder for [`BucketCriteriaAdditionalProperties`](crate::types::BucketCriteriaAdditionalProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BucketCriteriaAdditionalPropertiesBuilder {
    pub(crate) eq: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) gt: ::std::option::Option<i64>,
    pub(crate) gte: ::std::option::Option<i64>,
    pub(crate) lt: ::std::option::Option<i64>,
    pub(crate) lte: ::std::option::Option<i64>,
    pub(crate) neq: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
}
impl BucketCriteriaAdditionalPropertiesBuilder {
    /// Appends an item to `eq`.
    ///
    /// To override the contents of this collection use [`set_eq`](Self::set_eq).
    ///
    /// <p>The value for the property matches (equals) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn eq(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.eq.unwrap_or_default();
        v.push(input.into());
        self.eq = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value for the property matches (equals) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn set_eq(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.eq = input;
        self
    }
    /// <p>The value for the property matches (equals) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn get_eq(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.eq
    }
    /// <p>The value for the property is greater than the specified value.</p>
    pub fn gt(mut self, input: i64) -> Self {
        self.gt = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value for the property is greater than the specified value.</p>
    pub fn set_gt(mut self, input: ::std::option::Option<i64>) -> Self {
        self.gt = input;
        self
    }
    /// <p>The value for the property is greater than the specified value.</p>
    pub fn get_gt(&self) -> &::std::option::Option<i64> {
        &self.gt
    }
    /// <p>The value for the property is greater than or equal to the specified value.</p>
    pub fn gte(mut self, input: i64) -> Self {
        self.gte = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value for the property is greater than or equal to the specified value.</p>
    pub fn set_gte(mut self, input: ::std::option::Option<i64>) -> Self {
        self.gte = input;
        self
    }
    /// <p>The value for the property is greater than or equal to the specified value.</p>
    pub fn get_gte(&self) -> &::std::option::Option<i64> {
        &self.gte
    }
    /// <p>The value for the property is less than the specified value.</p>
    pub fn lt(mut self, input: i64) -> Self {
        self.lt = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value for the property is less than the specified value.</p>
    pub fn set_lt(mut self, input: ::std::option::Option<i64>) -> Self {
        self.lt = input;
        self
    }
    /// <p>The value for the property is less than the specified value.</p>
    pub fn get_lt(&self) -> &::std::option::Option<i64> {
        &self.lt
    }
    /// <p>The value for the property is less than or equal to the specified value.</p>
    pub fn lte(mut self, input: i64) -> Self {
        self.lte = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value for the property is less than or equal to the specified value.</p>
    pub fn set_lte(mut self, input: ::std::option::Option<i64>) -> Self {
        self.lte = input;
        self
    }
    /// <p>The value for the property is less than or equal to the specified value.</p>
    pub fn get_lte(&self) -> &::std::option::Option<i64> {
        &self.lte
    }
    /// Appends an item to `neq`.
    ///
    /// To override the contents of this collection use [`set_neq`](Self::set_neq).
    ///
    /// <p>The value for the property doesn't match (doesn't equal) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn neq(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.neq.unwrap_or_default();
        v.push(input.into());
        self.neq = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value for the property doesn't match (doesn't equal) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn set_neq(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.neq = input;
        self
    }
    /// <p>The value for the property doesn't match (doesn't equal) the specified value. If you specify multiple values, Amazon Macie uses OR logic to join the values.</p>
    pub fn get_neq(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.neq
    }
    /// <p>The name of the bucket begins with the specified value.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket begins with the specified value.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>The name of the bucket begins with the specified value.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// Consumes the builder and constructs a [`BucketCriteriaAdditionalProperties`](crate::types::BucketCriteriaAdditionalProperties).
    pub fn build(self) -> crate::types::BucketCriteriaAdditionalProperties {
        crate::types::BucketCriteriaAdditionalProperties {
            eq: self.eq,
            gt: self.gt,
            gte: self.gte,
            lt: self.lt,
            lte: self.lte,
            neq: self.neq,
            prefix: self.prefix,
        }
    }
}
