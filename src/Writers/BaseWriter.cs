using System.Collections.Generic;
using System.Threading.Tasks;

namespace Sharphound.Writers
{
    public abstract class BaseWriter<T>
    {
        protected readonly string DataType;
        protected readonly List<T> Queue;
        private bool _fileCreated;
        protected int Count;
        protected bool NoOp;

        internal BaseWriter(string dataType)
        {
            DataType = dataType;
            Queue = new List<T>();
        }

        internal async Task AcceptObject(T item)
        {
            if (NoOp)
                return;
            if (!_fileCreated)
            {
                CreateFile();
                _fileCreated = true;
            }

            Queue.Add(item);
            Count++;
            if (Count % 30 == 0)
            {
                await WriteData();
                Queue.Clear();
            }
        }

        protected abstract Task WriteData();

        internal abstract Task FlushWriter();

        protected abstract void CreateFile();
    }
}