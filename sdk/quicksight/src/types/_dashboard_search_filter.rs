// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter that you apply when searching for dashboards.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DashboardSearchFilter {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StringEquals"</code>. Valid values are <code>"StringEquals"</code> and <code>"StringLike"</code>.</p>
    /// <p>If you set the operator value to <code>"StringEquals"</code>, you need to provide an ownership related filter in the <code>"NAME"</code> field and the arn of the user or group whose folders you want to search in the <code>"Value"</code> field. For example, <code>"Name":"DIRECT_QUICKSIGHT_OWNER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    /// <p>If you set the value to <code>"StringLike"</code>, you need to provide the name of the folders you are searching for. For example, <code>"Name":"DASHBOARD_NAME", "Operator": "StringLike", "Value": "Test"</code>. The <code>"StringLike"</code> operator only supports the <code>NAME</code> value <code>DASHBOARD_NAME</code>.</p>
    pub operator: crate::types::FilterOperator,
    /// <p>The name of the value that you want to use as a filter, for example, <code>"Name": "QUICKSIGHT_OWNER"</code>.</p>
    /// <p>Valid values are defined as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the dashboards's owners or viewers are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_SOLE_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as the only owner of the dashboard are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners or viewers of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DASHBOARD_NAME</code>: Any dashboards whose names have a substring match to this value will be returned.</p></li>
    /// </ul>
    pub name: ::std::option::Option<crate::types::DashboardFilterAttribute>,
    /// <p>The value of the named item, in this case <code>QUICKSIGHT_USER</code>, that you want to use as a filter, for example, <code>"Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl DashboardSearchFilter {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StringEquals"</code>. Valid values are <code>"StringEquals"</code> and <code>"StringLike"</code>.</p>
    /// <p>If you set the operator value to <code>"StringEquals"</code>, you need to provide an ownership related filter in the <code>"NAME"</code> field and the arn of the user or group whose folders you want to search in the <code>"Value"</code> field. For example, <code>"Name":"DIRECT_QUICKSIGHT_OWNER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    /// <p>If you set the value to <code>"StringLike"</code>, you need to provide the name of the folders you are searching for. For example, <code>"Name":"DASHBOARD_NAME", "Operator": "StringLike", "Value": "Test"</code>. The <code>"StringLike"</code> operator only supports the <code>NAME</code> value <code>DASHBOARD_NAME</code>.</p>
    pub fn operator(&self) -> &crate::types::FilterOperator {
        &self.operator
    }
    /// <p>The name of the value that you want to use as a filter, for example, <code>"Name": "QUICKSIGHT_OWNER"</code>.</p>
    /// <p>Valid values are defined as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the dashboards's owners or viewers are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_SOLE_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as the only owner of the dashboard are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners or viewers of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DASHBOARD_NAME</code>: Any dashboards whose names have a substring match to this value will be returned.</p></li>
    /// </ul>
    pub fn name(&self) -> ::std::option::Option<&crate::types::DashboardFilterAttribute> {
        self.name.as_ref()
    }
    /// <p>The value of the named item, in this case <code>QUICKSIGHT_USER</code>, that you want to use as a filter, for example, <code>"Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl DashboardSearchFilter {
    /// Creates a new builder-style object to manufacture [`DashboardSearchFilter`](crate::types::DashboardSearchFilter).
    pub fn builder() -> crate::types::builders::DashboardSearchFilterBuilder {
        crate::types::builders::DashboardSearchFilterBuilder::default()
    }
}

/// A builder for [`DashboardSearchFilter`](crate::types::DashboardSearchFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DashboardSearchFilterBuilder {
    pub(crate) operator: ::std::option::Option<crate::types::FilterOperator>,
    pub(crate) name: ::std::option::Option<crate::types::DashboardFilterAttribute>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl DashboardSearchFilterBuilder {
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StringEquals"</code>. Valid values are <code>"StringEquals"</code> and <code>"StringLike"</code>.</p>
    /// <p>If you set the operator value to <code>"StringEquals"</code>, you need to provide an ownership related filter in the <code>"NAME"</code> field and the arn of the user or group whose folders you want to search in the <code>"Value"</code> field. For example, <code>"Name":"DIRECT_QUICKSIGHT_OWNER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    /// <p>If you set the value to <code>"StringLike"</code>, you need to provide the name of the folders you are searching for. For example, <code>"Name":"DASHBOARD_NAME", "Operator": "StringLike", "Value": "Test"</code>. The <code>"StringLike"</code> operator only supports the <code>NAME</code> value <code>DASHBOARD_NAME</code>.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::FilterOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StringEquals"</code>. Valid values are <code>"StringEquals"</code> and <code>"StringLike"</code>.</p>
    /// <p>If you set the operator value to <code>"StringEquals"</code>, you need to provide an ownership related filter in the <code>"NAME"</code> field and the arn of the user or group whose folders you want to search in the <code>"Value"</code> field. For example, <code>"Name":"DIRECT_QUICKSIGHT_OWNER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    /// <p>If you set the value to <code>"StringLike"</code>, you need to provide the name of the folders you are searching for. For example, <code>"Name":"DASHBOARD_NAME", "Operator": "StringLike", "Value": "Test"</code>. The <code>"StringLike"</code> operator only supports the <code>NAME</code> value <code>DASHBOARD_NAME</code>.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::FilterOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The comparison operator that you want to use as a filter, for example <code>"Operator": "StringEquals"</code>. Valid values are <code>"StringEquals"</code> and <code>"StringLike"</code>.</p>
    /// <p>If you set the operator value to <code>"StringEquals"</code>, you need to provide an ownership related filter in the <code>"NAME"</code> field and the arn of the user or group whose folders you want to search in the <code>"Value"</code> field. For example, <code>"Name":"DIRECT_QUICKSIGHT_OWNER", "Operator": "StringEquals", "Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    /// <p>If you set the value to <code>"StringLike"</code>, you need to provide the name of the folders you are searching for. For example, <code>"Name":"DASHBOARD_NAME", "Operator": "StringLike", "Value": "Test"</code>. The <code>"StringLike"</code> operator only supports the <code>NAME</code> value <code>DASHBOARD_NAME</code>.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::FilterOperator> {
        &self.operator
    }
    /// <p>The name of the value that you want to use as a filter, for example, <code>"Name": "QUICKSIGHT_OWNER"</code>.</p>
    /// <p>Valid values are defined as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the dashboards's owners or viewers are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_SOLE_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as the only owner of the dashboard are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners or viewers of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DASHBOARD_NAME</code>: Any dashboards whose names have a substring match to this value will be returned.</p></li>
    /// </ul>
    pub fn name(mut self, input: crate::types::DashboardFilterAttribute) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the value that you want to use as a filter, for example, <code>"Name": "QUICKSIGHT_OWNER"</code>.</p>
    /// <p>Valid values are defined as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the dashboards's owners or viewers are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_SOLE_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as the only owner of the dashboard are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners or viewers of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DASHBOARD_NAME</code>: Any dashboards whose names have a substring match to this value will be returned.</p></li>
    /// </ul>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::DashboardFilterAttribute>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the value that you want to use as a filter, for example, <code>"Name": "QUICKSIGHT_OWNER"</code>.</p>
    /// <p>Valid values are defined as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the dashboards's owners or viewers are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_SOLE_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as the only owner of the dashboard are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DIRECT_QUICKSIGHT_VIEWER_OR_OWNER</code>: Provide an ARN of a user or group, and any dashboards with that ARN listed as one of the owners or viewers of the dashboards are returned. Implicit permissions from folders or groups are not considered.</p></li>
    /// <li>
    /// <p><code>DASHBOARD_NAME</code>: Any dashboards whose names have a substring match to this value will be returned.</p></li>
    /// </ul>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::DashboardFilterAttribute> {
        &self.name
    }
    /// <p>The value of the named item, in this case <code>QUICKSIGHT_USER</code>, that you want to use as a filter, for example, <code>"Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the named item, in this case <code>QUICKSIGHT_USER</code>, that you want to use as a filter, for example, <code>"Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the named item, in this case <code>QUICKSIGHT_USER</code>, that you want to use as a filter, for example, <code>"Value": "arn:aws:quicksight:us-east-1:1:user/default/UserName1"</code>.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`DashboardSearchFilter`](crate::types::DashboardSearchFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`operator`](crate::types::builders::DashboardSearchFilterBuilder::operator)
    pub fn build(self) -> ::std::result::Result<crate::types::DashboardSearchFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DashboardSearchFilter {
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building DashboardSearchFilter",
                )
            })?,
            name: self.name,
            value: self.value,
        })
    }
}
