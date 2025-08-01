// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateResourceOutput {
    /// <p>The Amazon resource name (ARN) of the application that was augmented with attributes.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon resource name (ARN) that specifies the resource.</p>
    pub resource_arn: ::std::option::Option<::std::string::String>,
    /// <p>Determines whether an application tag is applied or skipped.</p>
    pub options: ::std::option::Option<::std::vec::Vec<crate::types::AssociationOption>>,
    _request_id: Option<String>,
}
impl AssociateResourceOutput {
    /// <p>The Amazon resource name (ARN) of the application that was augmented with attributes.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>The Amazon resource name (ARN) that specifies the resource.</p>
    pub fn resource_arn(&self) -> ::std::option::Option<&str> {
        self.resource_arn.as_deref()
    }
    /// <p>Determines whether an application tag is applied or skipped.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.options.is_none()`.
    pub fn options(&self) -> &[crate::types::AssociationOption] {
        self.options.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for AssociateResourceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateResourceOutput {
    /// Creates a new builder-style object to manufacture [`AssociateResourceOutput`](crate::operation::associate_resource::AssociateResourceOutput).
    pub fn builder() -> crate::operation::associate_resource::builders::AssociateResourceOutputBuilder {
        crate::operation::associate_resource::builders::AssociateResourceOutputBuilder::default()
    }
}

/// A builder for [`AssociateResourceOutput`](crate::operation::associate_resource::AssociateResourceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateResourceOutputBuilder {
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_arn: ::std::option::Option<::std::string::String>,
    pub(crate) options: ::std::option::Option<::std::vec::Vec<crate::types::AssociationOption>>,
    _request_id: Option<String>,
}
impl AssociateResourceOutputBuilder {
    /// <p>The Amazon resource name (ARN) of the application that was augmented with attributes.</p>
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) of the application that was augmented with attributes.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) of the application that was augmented with attributes.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>The Amazon resource name (ARN) that specifies the resource.</p>
    pub fn resource_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) that specifies the resource.</p>
    pub fn set_resource_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) that specifies the resource.</p>
    pub fn get_resource_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_arn
    }
    /// Appends an item to `options`.
    ///
    /// To override the contents of this collection use [`set_options`](Self::set_options).
    ///
    /// <p>Determines whether an application tag is applied or skipped.</p>
    pub fn options(mut self, input: crate::types::AssociationOption) -> Self {
        let mut v = self.options.unwrap_or_default();
        v.push(input);
        self.options = ::std::option::Option::Some(v);
        self
    }
    /// <p>Determines whether an application tag is applied or skipped.</p>
    pub fn set_options(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AssociationOption>>) -> Self {
        self.options = input;
        self
    }
    /// <p>Determines whether an application tag is applied or skipped.</p>
    pub fn get_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssociationOption>> {
        &self.options
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateResourceOutput`](crate::operation::associate_resource::AssociateResourceOutput).
    pub fn build(self) -> crate::operation::associate_resource::AssociateResourceOutput {
        crate::operation::associate_resource::AssociateResourceOutput {
            application_arn: self.application_arn,
            resource_arn: self.resource_arn,
            options: self.options,
            _request_id: self._request_id,
        }
    }
}
