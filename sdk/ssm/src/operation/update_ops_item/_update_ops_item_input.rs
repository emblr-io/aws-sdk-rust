// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateOpsItemInput {
    /// <p>User-defined text that contains information about the OpsItem, in Markdown format.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Add new keys or edit existing key-value pairs of the OperationalData map in the OpsItem object.</p>
    /// <p>Operational data is custom data that provides useful reference details about the OpsItem. For example, you can specify log files, error strings, license keys, troubleshooting tips, or other relevant data. You enter operational data as key-value pairs. The key has a maximum length of 128 characters. The value has a maximum size of 20 KB.</p><important>
    /// <p>Operational data keys <i>can't</i> begin with the following: <code>amazon</code>, <code>aws</code>, <code>amzn</code>, <code>ssm</code>, <code>/amazon</code>, <code>/aws</code>, <code>/amzn</code>, <code>/ssm</code>.</p>
    /// </important>
    /// <p>You can choose to make the data searchable by other users in the account or you can restrict search access. Searchable data means that all users with access to the OpsItem Overview page (as provided by the <code>DescribeOpsItems</code> API operation) can view and search on the specified data. Operational data that isn't searchable is only viewable by users who have access to the OpsItem (as provided by the <code>GetOpsItem</code> API operation).</p>
    /// <p>Use the <code>/aws/resources</code> key in OperationalData to specify a related resource in the request. Use the <code>/aws/automations</code> key in OperationalData to associate an Automation runbook with the OpsItem. To view Amazon Web Services CLI example commands that use these keys, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-manually-create-OpsItems.html">Creating OpsItems manually</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub operational_data: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::OpsItemDataValue>>,
    /// <p>Keys that you want to remove from the OperationalData map.</p>
    pub operational_data_to_delete: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The Amazon Resource Name (ARN) of an SNS topic where notifications are sent when this OpsItem is edited or changed.</p>
    pub notifications: ::std::option::Option<::std::vec::Vec<crate::types::OpsItemNotification>>,
    /// <p>The importance of this OpsItem in relation to other OpsItems in the system.</p>
    pub priority: ::std::option::Option<i32>,
    /// <p>One or more OpsItems that share something in common with the current OpsItems. For example, related OpsItems can include OpsItems with similar error messages, impacted resources, or statuses for the impacted resource.</p>
    pub related_ops_items: ::std::option::Option<::std::vec::Vec<crate::types::RelatedOpsItem>>,
    /// <p>The OpsItem status. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-working-with-OpsItems-editing-details.html">Editing OpsItem details</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub status: ::std::option::Option<crate::types::OpsItemStatus>,
    /// <p>The ID of the OpsItem.</p>
    pub ops_item_id: ::std::option::Option<::std::string::String>,
    /// <p>A short heading that describes the nature of the OpsItem and the impacted resource.</p>
    pub title: ::std::option::Option<::std::string::String>,
    /// <p>Specify a new category for an OpsItem.</p>
    pub category: ::std::option::Option<::std::string::String>,
    /// <p>Specify a new severity for an OpsItem.</p>
    pub severity: ::std::option::Option<::std::string::String>,
    /// <p>The time a runbook workflow started. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub actual_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time a runbook workflow ended. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub actual_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time specified in a change request for a runbook workflow to start. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub planned_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time specified in a change request for a runbook workflow to end. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub planned_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The OpsItem Amazon Resource Name (ARN).</p>
    pub ops_item_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateOpsItemInput {
    /// <p>User-defined text that contains information about the OpsItem, in Markdown format.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Add new keys or edit existing key-value pairs of the OperationalData map in the OpsItem object.</p>
    /// <p>Operational data is custom data that provides useful reference details about the OpsItem. For example, you can specify log files, error strings, license keys, troubleshooting tips, or other relevant data. You enter operational data as key-value pairs. The key has a maximum length of 128 characters. The value has a maximum size of 20 KB.</p><important>
    /// <p>Operational data keys <i>can't</i> begin with the following: <code>amazon</code>, <code>aws</code>, <code>amzn</code>, <code>ssm</code>, <code>/amazon</code>, <code>/aws</code>, <code>/amzn</code>, <code>/ssm</code>.</p>
    /// </important>
    /// <p>You can choose to make the data searchable by other users in the account or you can restrict search access. Searchable data means that all users with access to the OpsItem Overview page (as provided by the <code>DescribeOpsItems</code> API operation) can view and search on the specified data. Operational data that isn't searchable is only viewable by users who have access to the OpsItem (as provided by the <code>GetOpsItem</code> API operation).</p>
    /// <p>Use the <code>/aws/resources</code> key in OperationalData to specify a related resource in the request. Use the <code>/aws/automations</code> key in OperationalData to associate an Automation runbook with the OpsItem. To view Amazon Web Services CLI example commands that use these keys, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-manually-create-OpsItems.html">Creating OpsItems manually</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn operational_data(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::OpsItemDataValue>> {
        self.operational_data.as_ref()
    }
    /// <p>Keys that you want to remove from the OperationalData map.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.operational_data_to_delete.is_none()`.
    pub fn operational_data_to_delete(&self) -> &[::std::string::String] {
        self.operational_data_to_delete.as_deref().unwrap_or_default()
    }
    /// <p>The Amazon Resource Name (ARN) of an SNS topic where notifications are sent when this OpsItem is edited or changed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notifications.is_none()`.
    pub fn notifications(&self) -> &[crate::types::OpsItemNotification] {
        self.notifications.as_deref().unwrap_or_default()
    }
    /// <p>The importance of this OpsItem in relation to other OpsItems in the system.</p>
    pub fn priority(&self) -> ::std::option::Option<i32> {
        self.priority
    }
    /// <p>One or more OpsItems that share something in common with the current OpsItems. For example, related OpsItems can include OpsItems with similar error messages, impacted resources, or statuses for the impacted resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.related_ops_items.is_none()`.
    pub fn related_ops_items(&self) -> &[crate::types::RelatedOpsItem] {
        self.related_ops_items.as_deref().unwrap_or_default()
    }
    /// <p>The OpsItem status. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-working-with-OpsItems-editing-details.html">Editing OpsItem details</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OpsItemStatus> {
        self.status.as_ref()
    }
    /// <p>The ID of the OpsItem.</p>
    pub fn ops_item_id(&self) -> ::std::option::Option<&str> {
        self.ops_item_id.as_deref()
    }
    /// <p>A short heading that describes the nature of the OpsItem and the impacted resource.</p>
    pub fn title(&self) -> ::std::option::Option<&str> {
        self.title.as_deref()
    }
    /// <p>Specify a new category for an OpsItem.</p>
    pub fn category(&self) -> ::std::option::Option<&str> {
        self.category.as_deref()
    }
    /// <p>Specify a new severity for an OpsItem.</p>
    pub fn severity(&self) -> ::std::option::Option<&str> {
        self.severity.as_deref()
    }
    /// <p>The time a runbook workflow started. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn actual_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.actual_start_time.as_ref()
    }
    /// <p>The time a runbook workflow ended. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn actual_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.actual_end_time.as_ref()
    }
    /// <p>The time specified in a change request for a runbook workflow to start. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn planned_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.planned_start_time.as_ref()
    }
    /// <p>The time specified in a change request for a runbook workflow to end. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn planned_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.planned_end_time.as_ref()
    }
    /// <p>The OpsItem Amazon Resource Name (ARN).</p>
    pub fn ops_item_arn(&self) -> ::std::option::Option<&str> {
        self.ops_item_arn.as_deref()
    }
}
impl UpdateOpsItemInput {
    /// Creates a new builder-style object to manufacture [`UpdateOpsItemInput`](crate::operation::update_ops_item::UpdateOpsItemInput).
    pub fn builder() -> crate::operation::update_ops_item::builders::UpdateOpsItemInputBuilder {
        crate::operation::update_ops_item::builders::UpdateOpsItemInputBuilder::default()
    }
}

/// A builder for [`UpdateOpsItemInput`](crate::operation::update_ops_item::UpdateOpsItemInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateOpsItemInputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) operational_data: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::OpsItemDataValue>>,
    pub(crate) operational_data_to_delete: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) notifications: ::std::option::Option<::std::vec::Vec<crate::types::OpsItemNotification>>,
    pub(crate) priority: ::std::option::Option<i32>,
    pub(crate) related_ops_items: ::std::option::Option<::std::vec::Vec<crate::types::RelatedOpsItem>>,
    pub(crate) status: ::std::option::Option<crate::types::OpsItemStatus>,
    pub(crate) ops_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) title: ::std::option::Option<::std::string::String>,
    pub(crate) category: ::std::option::Option<::std::string::String>,
    pub(crate) severity: ::std::option::Option<::std::string::String>,
    pub(crate) actual_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) actual_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) planned_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) planned_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ops_item_arn: ::std::option::Option<::std::string::String>,
}
impl UpdateOpsItemInputBuilder {
    /// <p>User-defined text that contains information about the OpsItem, in Markdown format.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>User-defined text that contains information about the OpsItem, in Markdown format.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>User-defined text that contains information about the OpsItem, in Markdown format.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `operational_data`.
    ///
    /// To override the contents of this collection use [`set_operational_data`](Self::set_operational_data).
    ///
    /// <p>Add new keys or edit existing key-value pairs of the OperationalData map in the OpsItem object.</p>
    /// <p>Operational data is custom data that provides useful reference details about the OpsItem. For example, you can specify log files, error strings, license keys, troubleshooting tips, or other relevant data. You enter operational data as key-value pairs. The key has a maximum length of 128 characters. The value has a maximum size of 20 KB.</p><important>
    /// <p>Operational data keys <i>can't</i> begin with the following: <code>amazon</code>, <code>aws</code>, <code>amzn</code>, <code>ssm</code>, <code>/amazon</code>, <code>/aws</code>, <code>/amzn</code>, <code>/ssm</code>.</p>
    /// </important>
    /// <p>You can choose to make the data searchable by other users in the account or you can restrict search access. Searchable data means that all users with access to the OpsItem Overview page (as provided by the <code>DescribeOpsItems</code> API operation) can view and search on the specified data. Operational data that isn't searchable is only viewable by users who have access to the OpsItem (as provided by the <code>GetOpsItem</code> API operation).</p>
    /// <p>Use the <code>/aws/resources</code> key in OperationalData to specify a related resource in the request. Use the <code>/aws/automations</code> key in OperationalData to associate an Automation runbook with the OpsItem. To view Amazon Web Services CLI example commands that use these keys, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-manually-create-OpsItems.html">Creating OpsItems manually</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn operational_data(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::OpsItemDataValue) -> Self {
        let mut hash_map = self.operational_data.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.operational_data = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Add new keys or edit existing key-value pairs of the OperationalData map in the OpsItem object.</p>
    /// <p>Operational data is custom data that provides useful reference details about the OpsItem. For example, you can specify log files, error strings, license keys, troubleshooting tips, or other relevant data. You enter operational data as key-value pairs. The key has a maximum length of 128 characters. The value has a maximum size of 20 KB.</p><important>
    /// <p>Operational data keys <i>can't</i> begin with the following: <code>amazon</code>, <code>aws</code>, <code>amzn</code>, <code>ssm</code>, <code>/amazon</code>, <code>/aws</code>, <code>/amzn</code>, <code>/ssm</code>.</p>
    /// </important>
    /// <p>You can choose to make the data searchable by other users in the account or you can restrict search access. Searchable data means that all users with access to the OpsItem Overview page (as provided by the <code>DescribeOpsItems</code> API operation) can view and search on the specified data. Operational data that isn't searchable is only viewable by users who have access to the OpsItem (as provided by the <code>GetOpsItem</code> API operation).</p>
    /// <p>Use the <code>/aws/resources</code> key in OperationalData to specify a related resource in the request. Use the <code>/aws/automations</code> key in OperationalData to associate an Automation runbook with the OpsItem. To view Amazon Web Services CLI example commands that use these keys, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-manually-create-OpsItems.html">Creating OpsItems manually</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_operational_data(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::OpsItemDataValue>>,
    ) -> Self {
        self.operational_data = input;
        self
    }
    /// <p>Add new keys or edit existing key-value pairs of the OperationalData map in the OpsItem object.</p>
    /// <p>Operational data is custom data that provides useful reference details about the OpsItem. For example, you can specify log files, error strings, license keys, troubleshooting tips, or other relevant data. You enter operational data as key-value pairs. The key has a maximum length of 128 characters. The value has a maximum size of 20 KB.</p><important>
    /// <p>Operational data keys <i>can't</i> begin with the following: <code>amazon</code>, <code>aws</code>, <code>amzn</code>, <code>ssm</code>, <code>/amazon</code>, <code>/aws</code>, <code>/amzn</code>, <code>/ssm</code>.</p>
    /// </important>
    /// <p>You can choose to make the data searchable by other users in the account or you can restrict search access. Searchable data means that all users with access to the OpsItem Overview page (as provided by the <code>DescribeOpsItems</code> API operation) can view and search on the specified data. Operational data that isn't searchable is only viewable by users who have access to the OpsItem (as provided by the <code>GetOpsItem</code> API operation).</p>
    /// <p>Use the <code>/aws/resources</code> key in OperationalData to specify a related resource in the request. Use the <code>/aws/automations</code> key in OperationalData to associate an Automation runbook with the OpsItem. To view Amazon Web Services CLI example commands that use these keys, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-manually-create-OpsItems.html">Creating OpsItems manually</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_operational_data(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::OpsItemDataValue>> {
        &self.operational_data
    }
    /// Appends an item to `operational_data_to_delete`.
    ///
    /// To override the contents of this collection use [`set_operational_data_to_delete`](Self::set_operational_data_to_delete).
    ///
    /// <p>Keys that you want to remove from the OperationalData map.</p>
    pub fn operational_data_to_delete(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.operational_data_to_delete.unwrap_or_default();
        v.push(input.into());
        self.operational_data_to_delete = ::std::option::Option::Some(v);
        self
    }
    /// <p>Keys that you want to remove from the OperationalData map.</p>
    pub fn set_operational_data_to_delete(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.operational_data_to_delete = input;
        self
    }
    /// <p>Keys that you want to remove from the OperationalData map.</p>
    pub fn get_operational_data_to_delete(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.operational_data_to_delete
    }
    /// Appends an item to `notifications`.
    ///
    /// To override the contents of this collection use [`set_notifications`](Self::set_notifications).
    ///
    /// <p>The Amazon Resource Name (ARN) of an SNS topic where notifications are sent when this OpsItem is edited or changed.</p>
    pub fn notifications(mut self, input: crate::types::OpsItemNotification) -> Self {
        let mut v = self.notifications.unwrap_or_default();
        v.push(input);
        self.notifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an SNS topic where notifications are sent when this OpsItem is edited or changed.</p>
    pub fn set_notifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OpsItemNotification>>) -> Self {
        self.notifications = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an SNS topic where notifications are sent when this OpsItem is edited or changed.</p>
    pub fn get_notifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OpsItemNotification>> {
        &self.notifications
    }
    /// <p>The importance of this OpsItem in relation to other OpsItems in the system.</p>
    pub fn priority(mut self, input: i32) -> Self {
        self.priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The importance of this OpsItem in relation to other OpsItems in the system.</p>
    pub fn set_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.priority = input;
        self
    }
    /// <p>The importance of this OpsItem in relation to other OpsItems in the system.</p>
    pub fn get_priority(&self) -> &::std::option::Option<i32> {
        &self.priority
    }
    /// Appends an item to `related_ops_items`.
    ///
    /// To override the contents of this collection use [`set_related_ops_items`](Self::set_related_ops_items).
    ///
    /// <p>One or more OpsItems that share something in common with the current OpsItems. For example, related OpsItems can include OpsItems with similar error messages, impacted resources, or statuses for the impacted resource.</p>
    pub fn related_ops_items(mut self, input: crate::types::RelatedOpsItem) -> Self {
        let mut v = self.related_ops_items.unwrap_or_default();
        v.push(input);
        self.related_ops_items = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more OpsItems that share something in common with the current OpsItems. For example, related OpsItems can include OpsItems with similar error messages, impacted resources, or statuses for the impacted resource.</p>
    pub fn set_related_ops_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RelatedOpsItem>>) -> Self {
        self.related_ops_items = input;
        self
    }
    /// <p>One or more OpsItems that share something in common with the current OpsItems. For example, related OpsItems can include OpsItems with similar error messages, impacted resources, or statuses for the impacted resource.</p>
    pub fn get_related_ops_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RelatedOpsItem>> {
        &self.related_ops_items
    }
    /// <p>The OpsItem status. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-working-with-OpsItems-editing-details.html">Editing OpsItem details</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn status(mut self, input: crate::types::OpsItemStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OpsItem status. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-working-with-OpsItems-editing-details.html">Editing OpsItem details</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OpsItemStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The OpsItem status. For more information, see <a href="https://docs.aws.amazon.com/systems-manager/latest/userguide/OpsCenter-working-with-OpsItems-editing-details.html">Editing OpsItem details</a> in the <i>Amazon Web Services Systems Manager User Guide</i>.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OpsItemStatus> {
        &self.status
    }
    /// <p>The ID of the OpsItem.</p>
    /// This field is required.
    pub fn ops_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ops_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the OpsItem.</p>
    pub fn set_ops_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ops_item_id = input;
        self
    }
    /// <p>The ID of the OpsItem.</p>
    pub fn get_ops_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ops_item_id
    }
    /// <p>A short heading that describes the nature of the OpsItem and the impacted resource.</p>
    pub fn title(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.title = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short heading that describes the nature of the OpsItem and the impacted resource.</p>
    pub fn set_title(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.title = input;
        self
    }
    /// <p>A short heading that describes the nature of the OpsItem and the impacted resource.</p>
    pub fn get_title(&self) -> &::std::option::Option<::std::string::String> {
        &self.title
    }
    /// <p>Specify a new category for an OpsItem.</p>
    pub fn category(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.category = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify a new category for an OpsItem.</p>
    pub fn set_category(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.category = input;
        self
    }
    /// <p>Specify a new category for an OpsItem.</p>
    pub fn get_category(&self) -> &::std::option::Option<::std::string::String> {
        &self.category
    }
    /// <p>Specify a new severity for an OpsItem.</p>
    pub fn severity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.severity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify a new severity for an OpsItem.</p>
    pub fn set_severity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.severity = input;
        self
    }
    /// <p>Specify a new severity for an OpsItem.</p>
    pub fn get_severity(&self) -> &::std::option::Option<::std::string::String> {
        &self.severity
    }
    /// <p>The time a runbook workflow started. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn actual_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.actual_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time a runbook workflow started. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn set_actual_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.actual_start_time = input;
        self
    }
    /// <p>The time a runbook workflow started. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn get_actual_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.actual_start_time
    }
    /// <p>The time a runbook workflow ended. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn actual_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.actual_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time a runbook workflow ended. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn set_actual_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.actual_end_time = input;
        self
    }
    /// <p>The time a runbook workflow ended. Currently reported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn get_actual_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.actual_end_time
    }
    /// <p>The time specified in a change request for a runbook workflow to start. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn planned_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.planned_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time specified in a change request for a runbook workflow to start. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn set_planned_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.planned_start_time = input;
        self
    }
    /// <p>The time specified in a change request for a runbook workflow to start. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn get_planned_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.planned_start_time
    }
    /// <p>The time specified in a change request for a runbook workflow to end. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn planned_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.planned_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time specified in a change request for a runbook workflow to end. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn set_planned_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.planned_end_time = input;
        self
    }
    /// <p>The time specified in a change request for a runbook workflow to end. Currently supported only for the OpsItem type <code>/aws/changerequest</code>.</p>
    pub fn get_planned_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.planned_end_time
    }
    /// <p>The OpsItem Amazon Resource Name (ARN).</p>
    pub fn ops_item_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ops_item_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OpsItem Amazon Resource Name (ARN).</p>
    pub fn set_ops_item_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ops_item_arn = input;
        self
    }
    /// <p>The OpsItem Amazon Resource Name (ARN).</p>
    pub fn get_ops_item_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ops_item_arn
    }
    /// Consumes the builder and constructs a [`UpdateOpsItemInput`](crate::operation::update_ops_item::UpdateOpsItemInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_ops_item::UpdateOpsItemInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_ops_item::UpdateOpsItemInput {
            description: self.description,
            operational_data: self.operational_data,
            operational_data_to_delete: self.operational_data_to_delete,
            notifications: self.notifications,
            priority: self.priority,
            related_ops_items: self.related_ops_items,
            status: self.status,
            ops_item_id: self.ops_item_id,
            title: self.title,
            category: self.category,
            severity: self.severity,
            actual_start_time: self.actual_start_time,
            actual_end_time: self.actual_end_time,
            planned_start_time: self.planned_start_time,
            planned_end_time: self.planned_end_time,
            ops_item_arn: self.ops_item_arn,
        })
    }
}
