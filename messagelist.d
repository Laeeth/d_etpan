module messagelist;

//===================
// print message list

/* get the message list and display it */

  string closeFolder()
  {

  }
  string deleteFolder()
  {

  }

  string renameFolder(string oldname, string newname)
  {

  }
  bool folderExists(string folder)
  {

  }

  string folderStatus(string folder, string[] what)
  {

  }

  string getFolderDelimiter()
  {

  }

  string[2][] getACL(string folder)
  {

  }

  string setACL(string folder, string who, string what)
  {

  }


  string createFolder(string folder)
  {

  }

  string subscribeFolder(string folder)
  {

  }
  string unSubscribeFolder(string folder)
  {
    
  }

  string[3][] xlistFolders(string directory, string pattern)
  {
    
  }
  string[] expunge()
  {

  }

  string[3][] listFolders(string directory, string pattern)
  {

  }

  string[3][] listSubscribedFolders(string directory, string pattern)
  {

  }
  void appendMessage(string folder, Message message, Flags flags, DateTime msgtime)
  {

  }

  string[2][3] namespace()
  {

  }

  string[2][] noOp()
  {

  }

  version(0) // implement later - for gmail etc
  {
    string oauth2Login(string user, string accessToken)
    {

    }

    string oauthLogin(string user, string accessToken)
    {

    }
  }
struct ETFolder
{
  mailfolder *folder;

  this(mailstorage* storage, string path)
  {
    this.session=session;
    throwOnException(folder = mailfolder_new(storage, path, NULL));
    throwOnException( mailfolder_connect(folder),MAIL_NO_ERROR));
  }

  ~this()
  {
    mailfolder_free(folder);   
  }

  string[] getMessageList()
  {
    return getMessageList(false);
  }
  
  string[] getMessageList(bool tree)
  {
    string[] ret;
    alias session=folder.fld_session;
    int r;
    uint i,count;
    mailmessage_list * env_list;

    throwOnException(mailsession_get_messages_list(session, &env_list),MAIL_NO_ERROR);
    scope(exit)
      mailmessage_list_free(env_list);
    throwOnException( mailsession_get_envelopes_list(session, env_list),MAIL_NO_ERROR);

    if (tree)    
    {
      mailmessage_tree * env_tree;
      MMAPString * prefix;
      throwOnException( mail_build_thread(MAIL_THREAD_REFERENCES_NO_SUBJECT, DEST_CHARSET, env_list, &env_tree, mailthread_tree_timecomp),MAIL_NO_ERROR);
      scope(exit) {  mailmessage_tree_free_recursive(env_tree);  mailmessage_list_free(env_list); }
      count = 0;
      throwOnError(prefix = mmap_string_new(""));
      scope(exit {  mailmessage_tree_free_recursive(env_tree);  mailmessage_list_free(env_list); mmap_string_free(prefix);}
      ret~=display_sub_tree(prefix, env_tree, 0, 0, pcount);
    }

    else
    {
      foreach(i;0..carray_count(env_list.msg_tab))
      {
        mailmessage * msg=carray_get(env_list.msg_tab, i);
        throwOnException(msg.msg_fields);
        ret~=getMailInfo("", msg);
      }
    }
    return ret;
  }

// FRM Message Tree

  void display_sub_tree(MMAPString * prefix, mailmessage_tree * msg_tree, int level, int has_next, uint * pcount)
  {
    carray * list;
    uint cur;
    
    if (msg_tree.node_msg != NULL) {
      print_mail_info(prefix.str, msg_tree.node_msg);
      (* pcount) ++;
    }

    list = msg_tree.node_children;
    
    if (carray_count(list) != 0)
    {
      char[2] old_prefix;
        
      if (level > 1)
      {
        memcpy(old_prefix, prefix.str + prefix.len - 2, 2);
        if (has_next)
          memcpy(prefix.str + prefix.len - 2, "| ", 2);
        else
          memcpy(prefix.str + prefix.len - 2, "  ", 2);
      }
      foreach(cur;0..carray_count(list))
      {
        int sub_has_next;
        
        if (cur != carray_count(list) - 1)
        {
          if (level > 0)
          {
            if (mmap_string_append(prefix, "+-") == NULL)
              return;
          }
          sub_has_next = 1;
        }
        else
        {
          if (level > 0) {
            if (mmap_string_append(prefix, "\\-") == NULL)
              return;
          }
          sub_has_next = 0;
        }

        display_sub_tree(prefix, carray_get(list, cur), level + 1, sub_has_next, pcount);
        if (mmap_string_truncate(prefix, prefix.len - 2) == NULL)
          return;
        
      }
      if (level > 1) {
        memcpy(prefix.str + prefix.len - 2, old_prefix, 2);
      }
    }
  }
}
