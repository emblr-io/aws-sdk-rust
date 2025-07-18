// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateAppInput {
    /// <p>Name of the application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The optional description for an app.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) of the resiliency policy. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:resiliency-policy/<code>policy-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub policy_arn: ::std::option::Option<::std::string::String>,
    /// <p>Tags assigned to the resource. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key/value pair.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Used for an idempotency token. A client token is a unique, case-sensitive string of up to 64 ASCII characters. You should not reuse the same client token for other API requests.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Assessment execution schedule with 'Daily' or 'Disabled' values.</p>
    pub assessment_schedule: ::std::option::Option<crate::types::AppAssessmentScheduleType>,
    /// <p>Defines the roles and credentials that Resilience Hub would use while creating the application, importing its resources, and running an assessment.</p>
    pub permission_model: ::std::option::Option<crate::types::PermissionModel>,
    /// <p>The list of events you would like to subscribe and get notification for. Currently, Resilience Hub supports only <b>Drift detected</b> and <b>Scheduled assessment failure</b> events notification.</p>
    pub event_subscriptions: ::std::option::Option<::std::vec::Vec<crate::types::EventSubscription>>,
    /// <p>Amazon Resource Name (ARN) of Resource Groups group that is integrated with an AppRegistry application. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub aws_application_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAppInput {
    /// <p>Name of the application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The optional description for an app.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) of the resiliency policy. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:resiliency-policy/<code>policy-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn policy_arn(&self) -> ::std::option::Option<&str> {
        self.policy_arn.as_deref()
    }
    /// <p>Tags assigned to the resource. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key/value pair.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Used for an idempotency token. A client token is a unique, case-sensitive string of up to 64 ASCII characters. You should not reuse the same client token for other API requests.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Assessment execution schedule with 'Daily' or 'Disabled' values.</p>
    pub fn assessment_schedule(&self) -> ::std::option::Option<&crate::types::AppAssessmentScheduleType> {
        self.assessment_schedule.as_ref()
    }
    /// <p>Defines the roles and credentials that Resilience Hub would use while creating the application, importing its resources, and running an assessment.</p>
    pub fn permission_model(&self) -> ::std::option::Option<&crate::types::PermissionModel> {
        self.permission_model.as_ref()
    }
    /// <p>The list of events you would like to subscribe and get notification for. Currently, Resilience Hub supports only <b>Drift detected</b> and <b>Scheduled assessment failure</b> events notification.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.event_subscriptions.is_none()`.
    pub fn event_subscriptions(&self) -> &[crate::types::EventSubscription] {
        self.event_subscriptions.as_deref().unwrap_or_default()
    }
    /// <p>Amazon Resource Name (ARN) of Resource Groups group that is integrated with an AppRegistry application. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn aws_application_arn(&self) -> ::std::option::Option<&str> {
        self.aws_application_arn.as_deref()
    }
}
impl ::std::fmt::Debug for CreateAppInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAppInput");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("policy_arn", &self.policy_arn);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.field("assessment_schedule", &self.assessment_schedule);
        formatter.field("permission_model", &self.permission_model);
        formatter.field("event_subscriptions", &self.event_subscriptions);
        formatter.field("aws_application_arn", &self.aws_application_arn);
        formatter.finish()
    }
}
impl CreateAppInput {
    /// Creates a new builder-style object to manufacture [`CreateAppInput`](crate::operation::create_app::CreateAppInput).
    pub fn builder() -> crate::operation::create_app::builders::CreateAppInputBuilder {
        crate::operation::create_app::builders::CreateAppInputBuilder::default()
    }
}

/// A builder for [`CreateAppInput`](crate::operation::create_app::CreateAppInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateAppInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) policy_arn: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) assessment_schedule: ::std::option::Option<crate::types::AppAssessmentScheduleType>,
    pub(crate) permission_model: ::std::option::Option<crate::types::PermissionModel>,
    pub(crate) event_subscriptions: ::std::option::Option<::std::vec::Vec<crate::types::EventSubscription>>,
    pub(crate) aws_application_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAppInputBuilder {
    /// <p>Name of the application.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The optional description for an app.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The optional description for an app.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The optional description for an app.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Amazon Resource Name (ARN) of the resiliency policy. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:resiliency-policy/<code>policy-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn policy_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the resiliency policy. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:resiliency-policy/<code>policy-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_policy_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the resiliency policy. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:resiliency-policy/<code>policy-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_policy_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_arn
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags assigned to the resource. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key/value pair.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags assigned to the resource. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key/value pair.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags assigned to the resource. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key/value pair.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Used for an idempotency token. A client token is a unique, case-sensitive string of up to 64 ASCII characters. You should not reuse the same client token for other API requests.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Used for an idempotency token. A client token is a unique, case-sensitive string of up to 64 ASCII characters. You should not reuse the same client token for other API requests.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Used for an idempotency token. A client token is a unique, case-sensitive string of up to 64 ASCII characters. You should not reuse the same client token for other API requests.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Assessment execution schedule with 'Daily' or 'Disabled' values.</p>
    pub fn assessment_schedule(mut self, input: crate::types::AppAssessmentScheduleType) -> Self {
        self.assessment_schedule = ::std::option::Option::Some(input);
        self
    }
    /// <p>Assessment execution schedule with 'Daily' or 'Disabled' values.</p>
    pub fn set_assessment_schedule(mut self, input: ::std::option::Option<crate::types::AppAssessmentScheduleType>) -> Self {
        self.assessment_schedule = input;
        self
    }
    /// <p>Assessment execution schedule with 'Daily' or 'Disabled' values.</p>
    pub fn get_assessment_schedule(&self) -> &::std::option::Option<crate::types::AppAssessmentScheduleType> {
        &self.assessment_schedule
    }
    /// <p>Defines the roles and credentials that Resilience Hub would use while creating the application, importing its resources, and running an assessment.</p>
    pub fn permission_model(mut self, input: crate::types::PermissionModel) -> Self {
        self.permission_model = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the roles and credentials that Resilience Hub would use while creating the application, importing its resources, and running an assessment.</p>
    pub fn set_permission_model(mut self, input: ::std::option::Option<crate::types::PermissionModel>) -> Self {
        self.permission_model = input;
        self
    }
    /// <p>Defines the roles and credentials that Resilience Hub would use while creating the application, importing its resources, and running an assessment.</p>
    pub fn get_permission_model(&self) -> &::std::option::Option<crate::types::PermissionModel> {
        &self.permission_model
    }
    /// Appends an item to `event_subscriptions`.
    ///
    /// To override the contents of this collection use [`set_event_subscriptions`](Self::set_event_subscriptions).
    ///
    /// <p>The list of events you would like to subscribe and get notification for. Currently, Resilience Hub supports only <b>Drift detected</b> and <b>Scheduled assessment failure</b> events notification.</p>
    pub fn event_subscriptions(mut self, input: crate::types::EventSubscription) -> Self {
        let mut v = self.event_subscriptions.unwrap_or_default();
        v.push(input);
        self.event_subscriptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of events you would like to subscribe and get notification for. Currently, Resilience Hub supports only <b>Drift detected</b> and <b>Scheduled assessment failure</b> events notification.</p>
    pub fn set_event_subscriptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventSubscription>>) -> Self {
        self.event_subscriptions = input;
        self
    }
    /// <p>The list of events you would like to subscribe and get notification for. Currently, Resilience Hub supports only <b>Drift detected</b> and <b>Scheduled assessment failure</b> events notification.</p>
    pub fn get_event_subscriptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventSubscription>> {
        &self.event_subscriptions
    }
    /// <p>Amazon Resource Name (ARN) of Resource Groups group that is integrated with an AppRegistry application. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn aws_application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of Resource Groups group that is integrated with an AppRegistry application. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_aws_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_application_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of Resource Groups group that is integrated with an AppRegistry application. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_aws_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_application_arn
    }
    /// Consumes the builder and constructs a [`CreateAppInput`](crate::operation::create_app::CreateAppInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_app::CreateAppInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_app::CreateAppInput {
            name: self.name,
            description: self.description,
            policy_arn: self.policy_arn,
            tags: self.tags,
            client_token: self.client_token,
            assessment_schedule: self.assessment_schedule,
            permission_model: self.permission_model,
            event_subscriptions: self.event_subscriptions,
            aws_application_arn: self.aws_application_arn,
        })
    }
}
impl ::std::fmt::Debug for CreateAppInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAppInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("policy_arn", &self.policy_arn);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.field("assessment_schedule", &self.assessment_schedule);
        formatter.field("permission_model", &self.permission_model);
        formatter.field("event_subscriptions", &self.event_subscriptions);
        formatter.field("aws_application_arn", &self.aws_application_arn);
        formatter.finish()
    }
}
