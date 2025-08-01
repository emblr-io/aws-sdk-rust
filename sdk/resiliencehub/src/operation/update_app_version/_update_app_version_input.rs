// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAppVersionInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub app_arn: ::std::option::Option<::std::string::String>,
    /// <p>Additional configuration parameters for an Resilience Hub application. If you want to implement <code>additionalInfo</code> through the Resilience Hub console rather than using an API call, see <a href="https://docs.aws.amazon.com/resilience-hub/latest/userguide/app-config-param.html">Configure the application configuration parameters</a>.</p><note>
    /// <p>Currently, this parameter accepts a key-value mapping (in a string format) of only one failover region and one associated account.</p>
    /// <p>Key: <code>"failover-regions"</code></p>
    /// <p>Value: <code>"\[{"region":"&lt;REGION&gt;", "accounts":\[{"id":"&lt;ACCOUNT_ID&gt;"}\]}\]"</code></p>
    /// </note>
    pub additional_info: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl UpdateAppVersionInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn app_arn(&self) -> ::std::option::Option<&str> {
        self.app_arn.as_deref()
    }
    /// <p>Additional configuration parameters for an Resilience Hub application. If you want to implement <code>additionalInfo</code> through the Resilience Hub console rather than using an API call, see <a href="https://docs.aws.amazon.com/resilience-hub/latest/userguide/app-config-param.html">Configure the application configuration parameters</a>.</p><note>
    /// <p>Currently, this parameter accepts a key-value mapping (in a string format) of only one failover region and one associated account.</p>
    /// <p>Key: <code>"failover-regions"</code></p>
    /// <p>Value: <code>"\[{"region":"&lt;REGION&gt;", "accounts":\[{"id":"&lt;ACCOUNT_ID&gt;"}\]}\]"</code></p>
    /// </note>
    pub fn additional_info(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.additional_info.as_ref()
    }
}
impl UpdateAppVersionInput {
    /// Creates a new builder-style object to manufacture [`UpdateAppVersionInput`](crate::operation::update_app_version::UpdateAppVersionInput).
    pub fn builder() -> crate::operation::update_app_version::builders::UpdateAppVersionInputBuilder {
        crate::operation::update_app_version::builders::UpdateAppVersionInputBuilder::default()
    }
}

/// A builder for [`UpdateAppVersionInput`](crate::operation::update_app_version::UpdateAppVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAppVersionInputBuilder {
    pub(crate) app_arn: ::std::option::Option<::std::string::String>,
    pub(crate) additional_info: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl UpdateAppVersionInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    /// This field is required.
    pub fn app_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_app_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_app_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_arn
    }
    /// Adds a key-value pair to `additional_info`.
    ///
    /// To override the contents of this collection use [`set_additional_info`](Self::set_additional_info).
    ///
    /// <p>Additional configuration parameters for an Resilience Hub application. If you want to implement <code>additionalInfo</code> through the Resilience Hub console rather than using an API call, see <a href="https://docs.aws.amazon.com/resilience-hub/latest/userguide/app-config-param.html">Configure the application configuration parameters</a>.</p><note>
    /// <p>Currently, this parameter accepts a key-value mapping (in a string format) of only one failover region and one associated account.</p>
    /// <p>Key: <code>"failover-regions"</code></p>
    /// <p>Value: <code>"\[{"region":"&lt;REGION&gt;", "accounts":\[{"id":"&lt;ACCOUNT_ID&gt;"}\]}\]"</code></p>
    /// </note>
    pub fn additional_info(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.additional_info.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.additional_info = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Additional configuration parameters for an Resilience Hub application. If you want to implement <code>additionalInfo</code> through the Resilience Hub console rather than using an API call, see <a href="https://docs.aws.amazon.com/resilience-hub/latest/userguide/app-config-param.html">Configure the application configuration parameters</a>.</p><note>
    /// <p>Currently, this parameter accepts a key-value mapping (in a string format) of only one failover region and one associated account.</p>
    /// <p>Key: <code>"failover-regions"</code></p>
    /// <p>Value: <code>"\[{"region":"&lt;REGION&gt;", "accounts":\[{"id":"&lt;ACCOUNT_ID&gt;"}\]}\]"</code></p>
    /// </note>
    pub fn set_additional_info(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.additional_info = input;
        self
    }
    /// <p>Additional configuration parameters for an Resilience Hub application. If you want to implement <code>additionalInfo</code> through the Resilience Hub console rather than using an API call, see <a href="https://docs.aws.amazon.com/resilience-hub/latest/userguide/app-config-param.html">Configure the application configuration parameters</a>.</p><note>
    /// <p>Currently, this parameter accepts a key-value mapping (in a string format) of only one failover region and one associated account.</p>
    /// <p>Key: <code>"failover-regions"</code></p>
    /// <p>Value: <code>"\[{"region":"&lt;REGION&gt;", "accounts":\[{"id":"&lt;ACCOUNT_ID&gt;"}\]}\]"</code></p>
    /// </note>
    pub fn get_additional_info(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.additional_info
    }
    /// Consumes the builder and constructs a [`UpdateAppVersionInput`](crate::operation::update_app_version::UpdateAppVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_app_version::UpdateAppVersionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_app_version::UpdateAppVersionInput {
            app_arn: self.app_arn,
            additional_info: self.additional_info,
        })
    }
}
