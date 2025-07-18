// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A view is a structure that defines a set of filters that provide a view into the information in the Amazon Web Services Resource Explorer index. The filters specify which information from the index is visible to the users of the view. For example, you can specify filters that include only resources that are tagged with the key "ENV" and the value "DEVELOPMENT" in the results returned by this view. You could also create a second view that includes only resources that are tagged with "ENV" and "PRODUCTION".</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct View {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view.</p>
    pub view_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account that owns this view.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when this view was last modified.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>An <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of an Amazon Web Services account, an organization, or an organizational unit (OU) that specifies whether this view includes resources from only the specified Amazon Web Services account, all accounts in the specified organization, or all accounts in the specified OU.</p>
    /// <p>If not specified, the value defaults to the Amazon Web Services account used to call this operation.</p>
    pub scope: ::std::option::Option<::std::string::String>,
    /// <p>A structure that contains additional information about the view.</p>
    pub included_properties: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>,
    /// <p>An array of <code>SearchFilter</code> objects that specify which resources can be included in the results of queries made using this view.</p>
    pub filters: ::std::option::Option<crate::types::SearchFilter>,
}
impl View {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view.</p>
    pub fn view_arn(&self) -> ::std::option::Option<&str> {
        self.view_arn.as_deref()
    }
    /// <p>The Amazon Web Services account that owns this view.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The date and time when this view was last modified.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>An <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of an Amazon Web Services account, an organization, or an organizational unit (OU) that specifies whether this view includes resources from only the specified Amazon Web Services account, all accounts in the specified organization, or all accounts in the specified OU.</p>
    /// <p>If not specified, the value defaults to the Amazon Web Services account used to call this operation.</p>
    pub fn scope(&self) -> ::std::option::Option<&str> {
        self.scope.as_deref()
    }
    /// <p>A structure that contains additional information about the view.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.included_properties.is_none()`.
    pub fn included_properties(&self) -> &[crate::types::IncludedProperty] {
        self.included_properties.as_deref().unwrap_or_default()
    }
    /// <p>An array of <code>SearchFilter</code> objects that specify which resources can be included in the results of queries made using this view.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::SearchFilter> {
        self.filters.as_ref()
    }
}
impl ::std::fmt::Debug for View {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("View");
        formatter.field("view_arn", &self.view_arn);
        formatter.field("owner", &self.owner);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("scope", &self.scope);
        formatter.field("included_properties", &self.included_properties);
        formatter.field("filters", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl View {
    /// Creates a new builder-style object to manufacture [`View`](crate::types::View).
    pub fn builder() -> crate::types::builders::ViewBuilder {
        crate::types::builders::ViewBuilder::default()
    }
}

/// A builder for [`View`](crate::types::View).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct ViewBuilder {
    pub(crate) view_arn: ::std::option::Option<::std::string::String>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) scope: ::std::option::Option<::std::string::String>,
    pub(crate) included_properties: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>,
    pub(crate) filters: ::std::option::Option<crate::types::SearchFilter>,
}
impl ViewBuilder {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view.</p>
    pub fn view_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.view_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view.</p>
    pub fn set_view_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.view_arn = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of the view.</p>
    pub fn get_view_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.view_arn
    }
    /// <p>The Amazon Web Services account that owns this view.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account that owns this view.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The Amazon Web Services account that owns this view.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The date and time when this view was last modified.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when this view was last modified.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The date and time when this view was last modified.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// <p>An <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of an Amazon Web Services account, an organization, or an organizational unit (OU) that specifies whether this view includes resources from only the specified Amazon Web Services account, all accounts in the specified organization, or all accounts in the specified OU.</p>
    /// <p>If not specified, the value defaults to the Amazon Web Services account used to call this operation.</p>
    pub fn scope(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scope = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of an Amazon Web Services account, an organization, or an organizational unit (OU) that specifies whether this view includes resources from only the specified Amazon Web Services account, all accounts in the specified organization, or all accounts in the specified OU.</p>
    /// <p>If not specified, the value defaults to the Amazon Web Services account used to call this operation.</p>
    pub fn set_scope(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scope = input;
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon resource name (ARN)</a> of an Amazon Web Services account, an organization, or an organizational unit (OU) that specifies whether this view includes resources from only the specified Amazon Web Services account, all accounts in the specified organization, or all accounts in the specified OU.</p>
    /// <p>If not specified, the value defaults to the Amazon Web Services account used to call this operation.</p>
    pub fn get_scope(&self) -> &::std::option::Option<::std::string::String> {
        &self.scope
    }
    /// Appends an item to `included_properties`.
    ///
    /// To override the contents of this collection use [`set_included_properties`](Self::set_included_properties).
    ///
    /// <p>A structure that contains additional information about the view.</p>
    pub fn included_properties(mut self, input: crate::types::IncludedProperty) -> Self {
        let mut v = self.included_properties.unwrap_or_default();
        v.push(input);
        self.included_properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>A structure that contains additional information about the view.</p>
    pub fn set_included_properties(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>>) -> Self {
        self.included_properties = input;
        self
    }
    /// <p>A structure that contains additional information about the view.</p>
    pub fn get_included_properties(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::IncludedProperty>> {
        &self.included_properties
    }
    /// <p>An array of <code>SearchFilter</code> objects that specify which resources can be included in the results of queries made using this view.</p>
    pub fn filters(mut self, input: crate::types::SearchFilter) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of <code>SearchFilter</code> objects that specify which resources can be included in the results of queries made using this view.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::SearchFilter>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An array of <code>SearchFilter</code> objects that specify which resources can be included in the results of queries made using this view.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::SearchFilter> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`View`](crate::types::View).
    pub fn build(self) -> crate::types::View {
        crate::types::View {
            view_arn: self.view_arn,
            owner: self.owner,
            last_updated_at: self.last_updated_at,
            scope: self.scope,
            included_properties: self.included_properties,
            filters: self.filters,
        }
    }
}
impl ::std::fmt::Debug for ViewBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("ViewBuilder");
        formatter.field("view_arn", &self.view_arn);
        formatter.field("owner", &self.owner);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("scope", &self.scope);
        formatter.field("included_properties", &self.included_properties);
        formatter.field("filters", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
