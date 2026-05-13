using System;

namespace GPOwned.Shared
{
    public static class TaskSchedulerHelper
    {
        public static bool TaskExists(string dc, string taskName)
        {
            try
            {
                dynamic svc = CreateService(dc);
                var folder = svc.GetFolder("\\");
                folder.GetTask(taskName);
                return true;
            }
            catch { return false; }
        }

        public static bool DeleteTask(string dc, string taskName, out string error)
        {
            error = null;
            try
            {
                dynamic svc = CreateService(dc);
                var folder = svc.GetFolder("\\");
                folder.DeleteTask(taskName, 0);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static dynamic CreateService(string dc)
        {
            Type type = Type.GetTypeFromProgID("Schedule.Service", dc);
            dynamic svc = Activator.CreateInstance(type);
            svc.Connect(dc, null, null, null);
            return svc;
        }
    }
}
