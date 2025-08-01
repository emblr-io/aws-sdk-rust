// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeauthorizeDataShareOutput {
    /// <p>The Amazon Resource Name (ARN) of the datashare that the consumer is to use.</p>
    pub data_share_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the producer namespace.</p>
    pub producer_arn: ::std::option::Option<::std::string::String>,
    /// <p>A value that specifies whether the datashare can be shared to a publicly accessible cluster.</p>
    pub allow_publicly_accessible_consumers: ::std::option::Option<bool>,
    /// <p>A value that specifies when the datashare has an association between producer and data consumers.</p>
    pub data_share_associations: ::std::option::Option<::std::vec::Vec<crate::types::DataShareAssociation>>,
    /// <p>The identifier of a datashare to show its managing entity.</p>
    pub managed_by: ::std::option::Option<::std::string::String>,
    /// <p>The type of the datashare created by RegisterNamespace.</p>
    pub data_share_type: ::std::option::Option<crate::types::DataShareType>,
    _request_id: Option<String>,
}
impl DeauthorizeDataShareOutput {
    /// <p>The Amazon Resource Name (ARN) of the datashare that the consumer is to use.</p>
    pub fn data_share_arn(&self) -> ::std::option::Option<&str> {
        self.data_share_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the producer namespace.</p>
    pub fn producer_arn(&self) -> ::std::option::Option<&str> {
        self.producer_arn.as_deref()
    }
    /// <p>A value that specifies whether the datashare can be shared to a publicly accessible cluster.</p>
    pub fn allow_publicly_accessible_consumers(&self) -> ::std::option::Option<bool> {
        self.allow_publicly_accessible_consumers
    }
    /// <p>A value that specifies when the datashare has an association between producer and data consumers.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_share_associations.is_none()`.
    pub fn data_share_associations(&self) -> &[crate::types::DataShareAssociation] {
        self.data_share_associations.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of a datashare to show its managing entity.</p>
    pub fn managed_by(&self) -> ::std::option::Option<&str> {
        self.managed_by.as_deref()
    }
    /// <p>The type of the datashare created by RegisterNamespace.</p>
    pub fn data_share_type(&self) -> ::std::option::Option<&crate::types::DataShareType> {
        self.data_share_type.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeauthorizeDataShareOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeauthorizeDataShareOutput {
    /// Creates a new builder-style object to manufacture [`DeauthorizeDataShareOutput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareOutput).
    pub fn builder() -> crate::operation::deauthorize_data_share::builders::DeauthorizeDataShareOutputBuilder {
        crate::operation::deauthorize_data_share::builders::DeauthorizeDataShareOutputBuilder::default()
    }
}

/// A builder for [`DeauthorizeDataShareOutput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeauthorizeDataShareOutputBuilder {
    pub(crate) data_share_arn: ::std::option::Option<::std::string::String>,
    pub(crate) producer_arn: ::std::option::Option<::std::string::String>,
    pub(crate) allow_publicly_accessible_consumers: ::std::option::Option<bool>,
    pub(crate) data_share_associations: ::std::option::Option<::std::vec::Vec<crate::types::DataShareAssociation>>,
    pub(crate) managed_by: ::std::option::Option<::std::string::String>,
    pub(crate) data_share_type: ::std::option::Option<crate::types::DataShareType>,
    _request_id: Option<String>,
}
impl DeauthorizeDataShareOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the datashare that the consumer is to use.</p>
    pub fn data_share_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_share_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the datashare that the consumer is to use.</p>
    pub fn set_data_share_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_share_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the datashare that the consumer is to use.</p>
    pub fn get_data_share_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_share_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the producer namespace.</p>
    pub fn producer_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.producer_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the producer namespace.</p>
    pub fn set_producer_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.producer_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the producer namespace.</p>
    pub fn get_producer_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.producer_arn
    }
    /// <p>A value that specifies whether the datashare can be shared to a publicly accessible cluster.</p>
    pub fn allow_publicly_accessible_consumers(mut self, input: bool) -> Self {
        self.allow_publicly_accessible_consumers = ::std::option::Option::Some(input);
        self
    }
    /// <p>A value that specifies whether the datashare can be shared to a publicly accessible cluster.</p>
    pub fn set_allow_publicly_accessible_consumers(mut self, input: ::std::option::Option<bool>) -> Self {
        self.allow_publicly_accessible_consumers = input;
        self
    }
    /// <p>A value that specifies whether the datashare can be shared to a publicly accessible cluster.</p>
    pub fn get_allow_publicly_accessible_consumers(&self) -> &::std::option::Option<bool> {
        &self.allow_publicly_accessible_consumers
    }
    /// Appends an item to `data_share_associations`.
    ///
    /// To override the contents of this collection use [`set_data_share_associations`](Self::set_data_share_associations).
    ///
    /// <p>A value that specifies when the datashare has an association between producer and data consumers.</p>
    pub fn data_share_associations(mut self, input: crate::types::DataShareAssociation) -> Self {
        let mut v = self.data_share_associations.unwrap_or_default();
        v.push(input);
        self.data_share_associations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A value that specifies when the datashare has an association between producer and data consumers.</p>
    pub fn set_data_share_associations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataShareAssociation>>) -> Self {
        self.data_share_associations = input;
        self
    }
    /// <p>A value that specifies when the datashare has an association between producer and data consumers.</p>
    pub fn get_data_share_associations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataShareAssociation>> {
        &self.data_share_associations
    }
    /// <p>The identifier of a datashare to show its managing entity.</p>
    pub fn managed_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of a datashare to show its managing entity.</p>
    pub fn set_managed_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_by = input;
        self
    }
    /// <p>The identifier of a datashare to show its managing entity.</p>
    pub fn get_managed_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_by
    }
    /// <p>The type of the datashare created by RegisterNamespace.</p>
    pub fn data_share_type(mut self, input: crate::types::DataShareType) -> Self {
        self.data_share_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the datashare created by RegisterNamespace.</p>
    pub fn set_data_share_type(mut self, input: ::std::option::Option<crate::types::DataShareType>) -> Self {
        self.data_share_type = input;
        self
    }
    /// <p>The type of the datashare created by RegisterNamespace.</p>
    pub fn get_data_share_type(&self) -> &::std::option::Option<crate::types::DataShareType> {
        &self.data_share_type
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeauthorizeDataShareOutput`](crate::operation::deauthorize_data_share::DeauthorizeDataShareOutput).
    pub fn build(self) -> crate::operation::deauthorize_data_share::DeauthorizeDataShareOutput {
        crate::operation::deauthorize_data_share::DeauthorizeDataShareOutput {
            data_share_arn: self.data_share_arn,
            producer_arn: self.producer_arn,
            allow_publicly_accessible_consumers: self.allow_publicly_accessible_consumers,
            data_share_associations: self.data_share_associations,
            managed_by: self.managed_by,
            data_share_type: self.data_share_type,
            _request_id: self._request_id,
        }
    }
}
